rule Virus_Hijack_Trojan_GenericKDZ_79663_68_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_68_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6eb83867da27c8f8698ed20c99e62c11eae907902a6d6fcfb7cd2d5418b5e9db"

  strings:
    $s1 = "grAD&Dj" fullword ascii
    $s2 = ";^A,mINX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}