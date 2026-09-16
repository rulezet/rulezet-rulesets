rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_309 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_309.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c01396d9b4a1e9452cd1f0fb9d04bd42a550bcd4b37c2b9007a74a88c5291db5"

  strings:
    $s1 = "Sand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}