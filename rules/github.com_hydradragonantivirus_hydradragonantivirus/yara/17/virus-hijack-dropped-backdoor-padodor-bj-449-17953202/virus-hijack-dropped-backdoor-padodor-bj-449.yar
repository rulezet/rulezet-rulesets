rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_449 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_449.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0ad3a952f08b4d97a290f53b9c624edba4a2387af4e772278c0d1b88440b237"

  strings:
    $s1 = "^(iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}