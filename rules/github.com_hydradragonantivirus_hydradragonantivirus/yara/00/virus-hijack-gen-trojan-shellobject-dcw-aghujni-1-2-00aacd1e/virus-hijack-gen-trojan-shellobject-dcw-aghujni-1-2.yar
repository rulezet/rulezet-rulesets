rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3cdb519cba210689a115f86cf1554b3edcad5e12746e109ca7e373caad24fbe"

  strings:
    $s1 = "rOKa;[&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}