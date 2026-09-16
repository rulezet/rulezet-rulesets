rule Virus_Hijack_Trojan_GenericKDZ_105921_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b713d9d057b0993681878d4e6955223ffbef0789b9362d64bfada33fff848a10"

  strings:
    $s1 = "~k2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}