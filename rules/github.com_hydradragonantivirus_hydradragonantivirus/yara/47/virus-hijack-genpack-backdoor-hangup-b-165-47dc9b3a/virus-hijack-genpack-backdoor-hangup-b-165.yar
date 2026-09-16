rule Virus_Hijack_GenPack_Backdoor_Hangup_B_165 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_165.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcee34802285dc74556aa5470eea706daa05a6dd7fda09b5d608a591334e34e9"

  strings:
    $s1 = "-your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}