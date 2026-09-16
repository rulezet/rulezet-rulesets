rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_a4IOpRm_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@a4IOpRm_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a350dcc6724fd7579ace7574b709423a7d5706b5580ee65032bb9fc02e2cc7c8"

  strings:
    $s1 = "Symploce" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}