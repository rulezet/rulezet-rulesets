rule Virus_Hijack_Trojan_GenericKDZ_99416_35 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_35.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42de677f510a202c2b9e5b3fb819f33df0d94ab982c9e8d9897458159d2ce906"

  strings:
    $s1 = "o$User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}