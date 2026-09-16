import "pe"
rule visual_c_plus_plus_6_sp: Compiler {
  meta:
    author      = "Kevin Falcoz"
    date_create = "25/02/2013"
    description = "Miscrosoft Visual C++ 6.0 SPx"

  strings:
    $str1 = { 55 8B EC 83 EC 44 56 FF 15 ?? 10 40 00 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E }  

  condition:
    $str1 at (pe.entry_point)
}