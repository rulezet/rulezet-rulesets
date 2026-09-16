rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_600 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_600.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9aab8f02369801db3d482d667d5571481798ce6f4ceb90e18cf441593f974ad"

  strings:
    $s1 = ".6iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}