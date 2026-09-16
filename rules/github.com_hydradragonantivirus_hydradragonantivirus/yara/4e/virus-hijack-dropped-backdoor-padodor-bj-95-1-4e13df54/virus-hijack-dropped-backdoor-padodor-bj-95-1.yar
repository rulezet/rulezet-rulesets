rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_95_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_95_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289a340235d1506b025d28f14919381554ba8acd3758431ce011e0e19eef0bf6"

  strings:
    $s1 = "Output@" fullword ascii
    $s2 = "Sleep/Pointe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}