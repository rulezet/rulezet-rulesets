rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_727 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_727.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cf9db2e01149bba29267f8e82c46d2482533ce978d4324353dafb5ab2b6d640"

  strings:
    $s1 = ")'iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}