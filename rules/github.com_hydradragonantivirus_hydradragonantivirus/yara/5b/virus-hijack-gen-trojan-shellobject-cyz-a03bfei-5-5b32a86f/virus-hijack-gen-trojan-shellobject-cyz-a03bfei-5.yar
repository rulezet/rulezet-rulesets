rule Virus_Hijack_Gen_Trojan_ShellObject_CyZ_a03BfEi_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CyZ@a03BfEi_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dbf4c231cca5cfccf00da9ea60a37997ddd51998d21c164c85d18e72734f431"

  strings:
    $s1 = "RUMP}q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}