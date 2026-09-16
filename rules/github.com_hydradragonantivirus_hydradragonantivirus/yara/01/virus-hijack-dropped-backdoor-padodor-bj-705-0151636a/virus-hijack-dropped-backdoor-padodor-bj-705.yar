rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_705 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_705.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96bf72e74a97378789fedff1bf7954b2c50be7aae448357b1ab7624845bc1b54"

  strings:
    $s1 = "?iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}