rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_154 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_154.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89e5099c586681b463ff25c1516381008541e55221d6b5071b8f382e12dc6159"

  strings:
    $s1 = "];Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}