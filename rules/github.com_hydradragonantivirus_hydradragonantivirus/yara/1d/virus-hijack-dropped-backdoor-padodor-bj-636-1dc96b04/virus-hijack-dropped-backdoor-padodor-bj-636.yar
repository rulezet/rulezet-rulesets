rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_636 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_636.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96774e1aa74c9ef70a9765058359750737c3725c266440897ef63f9fbe637e0f"

  strings:
    $s1 = "-iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}