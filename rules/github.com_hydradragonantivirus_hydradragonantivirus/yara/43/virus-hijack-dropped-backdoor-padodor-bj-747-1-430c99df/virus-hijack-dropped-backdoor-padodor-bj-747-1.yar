rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_747_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_747_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d31e80dc7a5e9152996272188c5178c8817fe4f3b99d7d83d770b1a07510fddb"

  strings:
    $s1 = "SAin*RYuf" fullword ascii
    $s2 = "PoMey#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}