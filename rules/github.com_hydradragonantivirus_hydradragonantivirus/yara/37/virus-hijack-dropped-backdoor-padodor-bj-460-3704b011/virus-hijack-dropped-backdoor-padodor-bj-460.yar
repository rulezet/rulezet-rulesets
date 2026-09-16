rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_460 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_460.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6702abaa3488a51386aa3e925eadcef4cca2c3d753229d6862aff7e9dd96759"

  strings:
    $s1 = "Microsoft Ireland Operations Limited makes the l" fullword ascii
    $s2 = "and selling your products. Depending upon the type of industry`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}