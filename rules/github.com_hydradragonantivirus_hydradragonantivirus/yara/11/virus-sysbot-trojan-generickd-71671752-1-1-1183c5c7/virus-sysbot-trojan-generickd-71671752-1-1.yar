rule Virus_Sysbot_Trojan_GenericKD_71671752_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9652c47d50c4a9cbf7572ba73ba91c56b396156f5a45dc768e2d703426f4ae57"

  strings:
    $s1 = "Intel Graphics UI " fullword wide
    $s2 = "  2016. All rights reserved." fullword wide
    $s3 = "[ * ] STARTING..." fullword ascii
    $s4 = "[ * ] ENDING..." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}