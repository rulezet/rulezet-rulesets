rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCggSqg_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCggSqg_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6d21b0081fc0326ad9e943641d0a7119c7a3eeab97935600f6e95194ae3c231"

  strings:
    $s1 = "Catarrhine" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}