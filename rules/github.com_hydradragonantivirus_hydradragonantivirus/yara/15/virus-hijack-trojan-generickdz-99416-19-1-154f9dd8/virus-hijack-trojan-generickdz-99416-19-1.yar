rule Virus_Hijack_Trojan_GenericKDZ_99416_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "726817e3342454d602de94d5fb0a2438224fdb9b1ed09e6aff82d6d0267e6e76"

  strings:
    $s1 = "high!S9" fullword ascii
    $s2 = "zzH%CUke" fullword ascii
    $s3 = "Tuck<z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}