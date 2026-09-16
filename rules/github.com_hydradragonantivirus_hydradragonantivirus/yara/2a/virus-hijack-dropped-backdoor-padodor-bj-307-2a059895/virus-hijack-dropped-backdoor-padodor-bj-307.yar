rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_307 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_307.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9066e1fceeb3ee12b2329c489a1350115172aa4cb8b6e8266f680b3c0f58bdcb"

  strings:
    $s1 = "$[iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}