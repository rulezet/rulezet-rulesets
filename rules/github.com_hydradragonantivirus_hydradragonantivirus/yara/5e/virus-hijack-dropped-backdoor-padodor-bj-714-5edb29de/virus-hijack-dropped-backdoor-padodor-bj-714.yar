rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_714 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_714.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f1deb56f689b25d9b7480a4d85c9f30d05aea1ed1e6235970b8e903d464e540"

  strings:
    $s1 = ";|If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}