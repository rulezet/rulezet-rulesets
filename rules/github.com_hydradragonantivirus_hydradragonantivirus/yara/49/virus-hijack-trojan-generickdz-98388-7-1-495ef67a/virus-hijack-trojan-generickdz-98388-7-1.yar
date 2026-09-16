rule Virus_Hijack_Trojan_GenericKDZ_98388_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88adec32c64b7b5e26eafafc8e42cf5b9f90429f5c5c7c98d47529a7e6745e3c"

  strings:
    $s1 = ":-}sTet" fullword ascii
    $s2 = "z]SiDI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}