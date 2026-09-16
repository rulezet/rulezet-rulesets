rule Virus_Hijack_Trojan_GenericKDZ_105924_436_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_436_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e73ac408f645c4dd551a81b6a356ae0812fbe40c9776bb8bd98ffdf4976bd9b2"

  strings:
    $s1 = "X:Yees" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}