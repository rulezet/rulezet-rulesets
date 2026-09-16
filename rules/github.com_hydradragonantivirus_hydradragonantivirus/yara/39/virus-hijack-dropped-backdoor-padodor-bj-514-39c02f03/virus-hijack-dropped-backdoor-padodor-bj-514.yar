rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_514 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_514.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e88fde0dea2cd809fd50f02dd92fbda286d0ad788a9816cfeb55b577f70b55c2"

  strings:
    $s1 = "OMicrosoft Ireland Operations Limited makes the l" fullword ascii
    $s2 = "and selling your products. Depending upon the type of industry`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}