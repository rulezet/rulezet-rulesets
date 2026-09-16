rule Virus_Hijack_Trojan_GenericKDZ_74550_34_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeaac451f698ed0803396c134818793dada10ee1b59a009db2a70633b2cf3869"

  strings:
    $s1 = "2(gAge" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}