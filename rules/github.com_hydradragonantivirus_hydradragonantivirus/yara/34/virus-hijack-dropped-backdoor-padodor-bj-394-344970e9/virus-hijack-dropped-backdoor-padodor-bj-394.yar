rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_394 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_394.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6a880554e1d40a616ad8d55c57e81e3cf51dfbcdfd24c7bea51f8e688f5e65"

  strings:
    $s1 = "DiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}