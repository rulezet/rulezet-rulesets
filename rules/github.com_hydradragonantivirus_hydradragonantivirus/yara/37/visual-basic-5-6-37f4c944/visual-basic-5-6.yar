import "pe"
rule visual_basic_5_6: Compiler {
  meta:
    author      = "Kevin Falcoz"
    date_create = "24/02/2013"
    description = "Miscrosoft Visual Basic 5.0/6.0"

  strings:
    $str1 = { 68 ?? ?? ?? 00 E8 ?? FF FF FF 00 00 ?? 00 00 00 30 00 00 00 ?? 00 00 00 00 00 00 00 [16] 00 00 00 00 00 00 01 00 }

  condition:
    $str1 at (pe.entry_point)
}