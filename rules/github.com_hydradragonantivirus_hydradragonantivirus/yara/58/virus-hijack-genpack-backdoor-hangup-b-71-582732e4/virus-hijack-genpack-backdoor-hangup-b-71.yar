rule Virus_Hijack_GenPack_Backdoor_Hangup_B_71 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_71.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "180d6158628d71588ffbcd2c6ca316bd78a53099bedb4efba9ae40a515561b50"

  strings:
    $s1 = "(your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}