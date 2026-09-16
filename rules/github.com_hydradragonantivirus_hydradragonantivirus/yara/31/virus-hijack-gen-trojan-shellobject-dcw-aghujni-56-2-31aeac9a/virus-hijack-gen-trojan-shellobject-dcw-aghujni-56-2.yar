rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_56_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_56_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c1429af18633f78b9bb1a5ba562c6689d4f4bb8462e6081c3b5c169cc8cb472"

  strings:
    $s1 = "~;awee" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}