rule Virus_Danger_Gen_Trojan_ShellObject_h0Y_aGjJTmg_2 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.h0Y@aGjJTmg_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f82f15161fd35871da4973fae66dbc6060dd4d082043fecd991b3d9e9d085587"

  strings:
    $s1 = "jauthorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}