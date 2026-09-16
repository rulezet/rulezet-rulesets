rule Virus_Hijack_Trojan_GenericKDZ_74550_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f0257fd93d05256ade0be4a9c0478241b9aed3047cada43c7166febb97712b7"

  strings:
    $s1 = "VAri<n\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}