rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_24 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69d1e2943512ae8246336bdd97d922ca816725bf4e206e34bb6ed38b43f3b0c3"

  strings:
    $s1 = "ODAl)j" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}