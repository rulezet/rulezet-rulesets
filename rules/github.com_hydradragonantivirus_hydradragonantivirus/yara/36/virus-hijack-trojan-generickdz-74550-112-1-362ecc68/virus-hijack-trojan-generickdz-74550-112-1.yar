rule Virus_Hijack_Trojan_GenericKDZ_74550_112_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_112_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c47594c86fadb3a3de27a7d0c3e291c1a534606636de883d224765d71514115"

  strings:
    $s1 = "9se_`bONg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}