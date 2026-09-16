rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_452 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_452.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "113cf9a9af2a8d3a637d30d491f2adf019f1bf8ee169b39a395aa1dfd472a194"

  strings:
    $s1 = "?are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}