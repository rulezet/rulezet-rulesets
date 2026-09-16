rule Trojan_Sysbot_Trojan_Agent_FFWH {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.Agent.FFWH.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fe68bac5a64a7002db91e93a50e977cede626c9bd01d6a6b7194907202be163"

  strings:
    $s1 = "ft Visual Studio\\" fullword ascii
    $s2 = "Timer&" fullword ascii
    $s3 = "g#Conk" fullword ascii
    $s4 = "Copy@N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}