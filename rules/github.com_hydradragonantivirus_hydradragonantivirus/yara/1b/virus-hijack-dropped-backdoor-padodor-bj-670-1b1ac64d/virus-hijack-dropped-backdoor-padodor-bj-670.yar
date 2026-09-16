rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_670 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_670.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7361df59fc611e5b30c2ecb586a3803e51dc29ea7e3430b9d2ad20c4891e6c18"

  strings:
    $s1 = "-and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}