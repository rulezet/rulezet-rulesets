import "pe"
rule bcpp2 {
  meta:
    author      = "PEiD"
    description = "Borland C++ 1999"
    group       = "10"
    function    = "0"

  strings:
    $a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 ?? ?? ?? ?? A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 52 }

  condition:
    $a0 at pe.entry_point
}