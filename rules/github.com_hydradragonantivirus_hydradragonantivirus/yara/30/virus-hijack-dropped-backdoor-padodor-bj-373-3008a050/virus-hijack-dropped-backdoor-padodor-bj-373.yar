rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_373 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_373.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "617fde930152b593ba26e9536353d57596d22cd9cee51a42133110ebb3f207b3"

  strings:
    $s1 = "tmust be a Qualified Educational User to use soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}