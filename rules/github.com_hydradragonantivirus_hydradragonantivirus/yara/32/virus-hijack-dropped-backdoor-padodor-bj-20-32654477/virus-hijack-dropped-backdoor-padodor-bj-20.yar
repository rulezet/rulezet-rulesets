rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8669cf27e1f74e5703935876f8e838093e1eac603d3d2f6ad5ec892625262d68"

  strings:
    $s1 = ",iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}