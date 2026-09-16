rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_315 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_315.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c271534ecc8dffdedcce91a9da4b412170b65c15c02c9dd4b1809c7460028c3"

  strings:
    $s1 = "3iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}