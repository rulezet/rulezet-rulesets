rule Virus_Hijack_Trojan_GenericKDZ_103285_884_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_884_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa0fcb7e2cedd379046f08111fdca95cd21a33b5d9c7ca5aaba094b2ffc200c1"

  strings:
    $s1 = "oLaM;a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}