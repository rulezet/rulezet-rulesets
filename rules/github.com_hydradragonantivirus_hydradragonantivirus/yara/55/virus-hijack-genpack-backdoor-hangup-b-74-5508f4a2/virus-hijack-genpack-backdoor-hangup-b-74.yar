rule Virus_Hijack_GenPack_Backdoor_Hangup_B_74 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_74.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b46ef6beceb32ee0eeb36e30a59e8237cfb488872ef504cfc3881703891b9f4"

  strings:
    $s1 = "|your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}