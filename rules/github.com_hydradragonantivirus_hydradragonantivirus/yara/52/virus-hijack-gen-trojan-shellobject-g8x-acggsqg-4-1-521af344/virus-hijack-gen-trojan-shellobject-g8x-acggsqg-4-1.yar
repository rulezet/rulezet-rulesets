rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCggSqg_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCggSqg_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29c10012257abd29a9afed391b9a528a28b0ad97bcec5972e0b653853ccc4742"

  strings:
    $s1 = "Lutein" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}