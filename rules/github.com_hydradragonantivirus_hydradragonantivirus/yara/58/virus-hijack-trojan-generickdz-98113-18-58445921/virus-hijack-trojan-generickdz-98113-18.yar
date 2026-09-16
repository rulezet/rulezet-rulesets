rule Virus_Hijack_Trojan_GenericKDZ_98113_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf424c93278163e782fbc01c03e7fcfa405452a53c56e6df99e8692a4c222a01"

  strings:
    $s1 = "HarP 4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}