rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_279 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_279.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1071a58f56debe8e402b5dc970b0e8736350a84c7c55d3304e6a2c794d8f85f7"

  strings:
    $s1 = "-|are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}