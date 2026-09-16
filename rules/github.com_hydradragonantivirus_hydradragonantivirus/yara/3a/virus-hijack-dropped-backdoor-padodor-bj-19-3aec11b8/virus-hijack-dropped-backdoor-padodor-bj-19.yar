rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "907f180b4ea0f83947159af0002f00816552c34ee0fa6ade5f2dd757a18cfdc4"

  strings:
    $s1 = "MiiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}