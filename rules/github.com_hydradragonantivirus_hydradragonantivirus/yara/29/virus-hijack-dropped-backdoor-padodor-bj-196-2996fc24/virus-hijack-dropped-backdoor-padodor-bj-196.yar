rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_196 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_196.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f336fbe165987d7643615a1bc9f84329538c0da56e627a1a04b4718f7d4fe545"

  strings:
    $s1 = "K{iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}