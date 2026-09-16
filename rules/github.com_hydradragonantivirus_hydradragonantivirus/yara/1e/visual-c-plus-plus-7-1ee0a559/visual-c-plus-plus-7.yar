import "pe"
rule visual_c_plus_plus_7: Compiler {
  meta:
    author      = "Kevin Falcoz"
    date_create = "25/02/2013"
    description = "Miscrosoft Visual C++ 7.0"

  strings:
    $str1 = { 6A 60 68 [2] 40 00 E8 [2] 00 00 BF 94 00 00 00 8B C7 E8 [4] 89 65 E8 8B F4 89 3E 56 FF 15 [2] 40 00 8B 4E 10 89 0D }  
    $str2 = { 6A 0C 68 [4] E8 [4] 33 C0 40 89 45 E4 }

  condition:
    $str1 at (pe.entry_point) or $str2 at (pe.entry_point)
}