rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_120 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_120.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f49b50718d4a568b52c1e53064355fb0d8732d88e472ef597d9f3d0af1e01d53"

  strings:
    $s1 = "4:are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}