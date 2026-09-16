import "pe"
rule pemangle {
  meta:
    author      = "PEiD"
    description = "PEMangle -> Lord Julus"
    group       = "149"
    function    = "0"

  strings:
    $a0 = { 60 9C BE ?? ?? ?? ?? 8B FE B9 ?? ?? ?? ?? BB 44 52 4F 4C AD 33 C3 }

  condition:
    $a0 at pe.entry_point
}