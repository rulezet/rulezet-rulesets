rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_420 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_420.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87ab85c6cbc0ad4a414b0e5643e59189c158d271d08108599509dad24c8279bd"

  strings:
    $s1 = "7dand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}