rule Virus_Hijack_Backdoor_Hangup_B_268 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_268.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "468e18f3c801de814a5413f46838accf9927f5fb69378e029f3a6fa8664c6dc3"

  strings:
    $s1 = "Cyour entire employee population." fullword ascii
    $s2 = "jimP%i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}