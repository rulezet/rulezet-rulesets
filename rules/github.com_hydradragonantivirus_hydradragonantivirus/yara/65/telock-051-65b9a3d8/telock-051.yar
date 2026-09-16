import "pe"
rule telock_051 {
  meta:
    author      = "PEiD"
    description = "tElock 0.51 -> tE!"
    group       = "179"
    function    = "0"

  strings:
    $a0 = { C1 EE ?? 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 5E 8B FE 68 79 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }

  condition:
    $a0 at pe.entry_point
}