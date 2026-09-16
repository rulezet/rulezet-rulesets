import "pe"
rule watcom_c_h {
  meta:
    author      = "PEiD"
    description = "Watcom C/C++ EXE Heuristic Mode"
    group       = "17"
    function    = "0"

  strings:
    $a0 = { 53 51 52 55 89 E5 83 EC 08 B8 01 ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 03 }

  condition:
    $a0 at pe.entry_point
}