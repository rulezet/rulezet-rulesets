rule Virus_Hijack_GenPack_Backdoor_Hangup_B_369 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_369.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bb94a051efd22fe4b760f7a747b6f53f8917f6b0021ad0bb239f67dffb26b66"

  strings:
    $s1 = "Uyour entire employee population." fullword ascii
    $s2 = "WONG?+y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}