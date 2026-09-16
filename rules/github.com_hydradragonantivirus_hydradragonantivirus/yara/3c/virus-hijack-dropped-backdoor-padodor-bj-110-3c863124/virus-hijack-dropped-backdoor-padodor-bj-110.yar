rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_110 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_110.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cff8480c0b7fee36ee70d25c933f61dabad82d80649b06acdb849a1a02362610"

  strings:
    $s1 = "}active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}