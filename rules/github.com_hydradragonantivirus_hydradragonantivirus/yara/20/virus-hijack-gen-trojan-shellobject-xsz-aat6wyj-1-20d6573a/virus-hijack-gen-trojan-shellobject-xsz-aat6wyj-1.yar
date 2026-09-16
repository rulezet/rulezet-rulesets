rule Virus_Hijack_Gen_Trojan_ShellObject_xSZ_aaT6Wyj_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.xSZ@aaT6Wyj_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "123b561302832c7ac2f21c7a1767630d5dbb3b62f33f5646ac59edd770cf98fb"

  strings:
    $s1 = "Twhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}