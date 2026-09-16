rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_700 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_700.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72aa401450f111af39afd4ebcf8fc3d180d6b4f19b6d5cec3e306eccd80fa338"

  strings:
    $s1 = "]iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}