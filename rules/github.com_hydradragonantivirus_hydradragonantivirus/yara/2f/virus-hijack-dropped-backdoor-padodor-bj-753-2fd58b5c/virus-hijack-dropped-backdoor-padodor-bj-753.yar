rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_753 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_753.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11e1f25f51ed3c71b9854219bff0a3d31958915f4a530427ba5dfa557fa8c87f"

  strings:
    $s1 = "siLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}