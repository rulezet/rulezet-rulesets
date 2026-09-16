rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_772_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_772_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00fded350227fbd911c6056982682157d3f8ca92d43d3d7a977968ba17362171"

  strings:
    $s1 = "intruding" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}