rule Virus_Hijack_Trojan_GenericKDZ_105924_43_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_43_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da9348ad7224f2c17d47870e948b046b7c3169845dc97104e1eb0ce63ed65351"

  strings:
    $s1 = "o*flOW" fullword ascii
    $s2 = "s!AWIN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}