rule Virus_Hijack_Gen_Trojan_ShellObject_gyY_aWevApi_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyY@aWevApi_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb30f118c80e20d63b7b1ce4a1aab0a90f1846db6f4079bbea6696e9897e9494"

  strings:
    $s1 = "Murkiness" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}