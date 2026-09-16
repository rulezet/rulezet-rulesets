rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cf9a95d1d1dcca3f38c298215a78b19c2f45df0e47d1d2f7e96f2c30ef82ede"

  strings:
    $s1 = "~;awee" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}