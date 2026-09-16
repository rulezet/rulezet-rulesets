rule Virus_Hijack_Trojan_GenericKDZ_98113_383 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_383.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b38f9882f8c9d2ae2bf673fa5a08d47a3ab9587cbae85d697cb7f31ba1a92730"

  strings:
    $s1 = "Vby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}