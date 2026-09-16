rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_425 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_425.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc8979867b86f844bd4e09b2dbce3a6fc3dfe5aafc4fd31adc310887d622d307"

  strings:
    $s1 = "&are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}