rule Virus_Hijack_Trojan_GenericKDZ_98113_49 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_49.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "766eb6856d4910e8a34ffabb11778fafe2419d51ee6825c95f9e7089ea6b8f9b"

  strings:
    $s1 = "\"or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}