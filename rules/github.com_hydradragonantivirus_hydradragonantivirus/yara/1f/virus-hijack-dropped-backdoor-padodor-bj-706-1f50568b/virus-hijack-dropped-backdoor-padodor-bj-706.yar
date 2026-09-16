rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_706 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_706.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6704f887d4a3d7740eae0089d5d6600f745253bfe21a5c8eed89865553f4587c"

  strings:
    $s1 = "SHaM{[a" fullword ascii
    $s2 = "[fVp)WAnE}K{[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}