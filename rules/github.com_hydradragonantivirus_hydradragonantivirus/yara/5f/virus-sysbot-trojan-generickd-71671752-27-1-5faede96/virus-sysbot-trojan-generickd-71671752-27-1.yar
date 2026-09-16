rule Virus_Sysbot_Trojan_GenericKD_71671752_27_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_27_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f56246eeec5a332ef0110dfc0004fc663f8a95e19afc13e9f812bb333655e100"

  strings:
    $s1 = " AnchorFree Inc. All rights reserved." fullword wide
    $s2 = "<Module>{84d9e5cb-853d-4451-b4cb-c540771f2d9c}" fullword ascii
    $s3 = "Hotspot Shield 7.9.0" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}