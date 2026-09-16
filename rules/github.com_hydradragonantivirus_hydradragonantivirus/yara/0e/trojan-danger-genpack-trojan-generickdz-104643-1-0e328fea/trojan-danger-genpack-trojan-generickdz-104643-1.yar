rule Trojan_Danger_GenPack_Trojan_GenericKDZ_104643_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_GenPack.Trojan.GenericKDZ.104643_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e12c6c5fb463434f30890950a7b85201995c32b29f873b685f07770ff3ab36c3"

  strings:
    $s1 = "gram Files\\(7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}