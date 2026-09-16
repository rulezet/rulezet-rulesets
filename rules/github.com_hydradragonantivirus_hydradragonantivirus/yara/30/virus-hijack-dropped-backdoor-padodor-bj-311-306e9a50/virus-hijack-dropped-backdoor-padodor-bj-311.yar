rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_311 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_311.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ba7c1acf85ecb7a2731461e01dc1609a2e3b733f66fd0bec413a9c450a2ec70"

  strings:
    $s1 = "fare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}