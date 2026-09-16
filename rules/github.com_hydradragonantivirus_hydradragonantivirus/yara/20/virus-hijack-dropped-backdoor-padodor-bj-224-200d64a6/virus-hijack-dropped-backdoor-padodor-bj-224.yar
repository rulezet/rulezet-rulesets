rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_224 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_224.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee5a04a9d8f909e9d3dd42b0bf5f73263311ec1466cb13b043654c0aede05de2"

  strings:
    $s1 = "Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}