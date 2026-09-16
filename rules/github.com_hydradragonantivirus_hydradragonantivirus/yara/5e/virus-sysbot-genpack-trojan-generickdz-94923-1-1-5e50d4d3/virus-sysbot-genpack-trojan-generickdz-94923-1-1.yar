rule Virus_Sysbot_GenPack_Trojan_GenericKDZ_94923_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_GenPack.Trojan.GenericKDZ.94923_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209315b2e308b9bcbc900a4ac746312c83961ee122a81757425649ed02ad71a9"

  strings:
    $s1 = "OyEr'," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}