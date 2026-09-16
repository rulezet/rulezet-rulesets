rule Virus_Hijack_Trojan_GenericKDZ_98113_135_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_135_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e734f11e5c7c3cd45c58af1666f0568b97c33e8efb017044283870d08326b48"

  strings:
    $s1 = "<!dyer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}