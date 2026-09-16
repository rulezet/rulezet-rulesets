rule Virus_Hijack_Trojan_GenericKDZ_98388_33_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_33_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79f22140cebc4a1c8b6fa45c2d6a9e3e25b00afb710bf313fa1bd14da413931c"

  strings:
    $s1 = ">*toON" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}