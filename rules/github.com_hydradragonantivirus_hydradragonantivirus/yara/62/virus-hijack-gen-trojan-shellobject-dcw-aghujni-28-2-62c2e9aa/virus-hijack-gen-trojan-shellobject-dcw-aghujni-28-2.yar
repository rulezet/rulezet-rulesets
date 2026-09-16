rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_28_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_28_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3165a7d481393ed38b0c53a2c350514fdd1c216f19f5db9d0e302b7d6130772"

  strings:
    $s1 = "p$VAnG(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}