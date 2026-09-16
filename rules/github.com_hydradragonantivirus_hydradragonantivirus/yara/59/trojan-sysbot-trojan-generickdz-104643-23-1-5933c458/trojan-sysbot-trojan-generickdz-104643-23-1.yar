rule Trojan_Sysbot_Trojan_GenericKDZ_104643_23_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKDZ.104643_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c3f940bd54c415cb52a31ae99f97b5bae0c689de24b30c710ab79453ac4189b"

  strings:
    $s1 = "Task Scheduler.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}