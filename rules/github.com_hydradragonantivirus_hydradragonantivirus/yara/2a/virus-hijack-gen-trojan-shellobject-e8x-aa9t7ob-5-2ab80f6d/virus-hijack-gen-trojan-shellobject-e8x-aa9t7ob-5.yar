rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f2a2834507d1c7bc07c97317a68b44bad2d4bd26afda99a370603d3d2c12fda"

  strings:
    $s1 = "7whundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}