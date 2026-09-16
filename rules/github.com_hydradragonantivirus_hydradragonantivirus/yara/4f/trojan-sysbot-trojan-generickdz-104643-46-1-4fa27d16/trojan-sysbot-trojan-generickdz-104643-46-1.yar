rule Trojan_Sysbot_Trojan_GenericKDZ_104643_46_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKDZ.104643_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1782d63ae8018f01d60018b913009d7efaae17245168fbc2f84fc3464f3a1a8d"

  strings:
    $s1 = "Ruby 3.2.2 API Reference.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}