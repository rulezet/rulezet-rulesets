rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "378d91efdeb897b128f961b9d2e5783185111176b43ba61b3522b7fd98779bf2"

  strings:
    $s1 = "yiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}