rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_655 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_655.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67fb4280f8ebe1ad63e46b74871207412d1e0aabe38b3995aacf2757643b67ef"

  strings:
    $s1 = "dc}gLor[Ie" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}