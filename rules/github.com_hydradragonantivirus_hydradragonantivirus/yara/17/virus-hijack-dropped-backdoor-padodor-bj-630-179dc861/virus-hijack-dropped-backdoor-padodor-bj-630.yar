rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_630 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_630.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7f1597e33c11882dbfdfa9276dd35fd487c640dfe5ca66b9eafca4d1fe8daef"

  strings:
    $s1 = "stiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}