rule Virus_Hijack_Trojan_GenericKDZ_105924_367_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_367_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91d8147ed87db0c47ee0ae67e919b9b28927066aabba9e7a97ec00480d8fbf06"

  strings:
    $s1 = "\"coNER" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}