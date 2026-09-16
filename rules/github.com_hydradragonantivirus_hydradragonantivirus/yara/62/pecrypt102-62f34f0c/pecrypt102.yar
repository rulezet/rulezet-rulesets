import "pe"
rule pecrypt102 {
  meta:
    author      = "PEiD"
    description = "PE Crypt 1.02 -> random, killa & acpizer"
    group       = "141"
    function    = "0"

  strings:
    $a0 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 }

  condition:
    $a0 at pe.entry_point
}