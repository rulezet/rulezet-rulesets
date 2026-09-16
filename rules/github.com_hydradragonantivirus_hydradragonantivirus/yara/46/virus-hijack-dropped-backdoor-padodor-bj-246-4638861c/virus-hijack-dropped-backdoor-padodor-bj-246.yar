rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_246 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_246.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7877c4ef0ba0fc2938fc6c1c2dd0bacbee4064786a08cf344185ab8f0a3bb333"

  strings:
    $s1 = " Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}