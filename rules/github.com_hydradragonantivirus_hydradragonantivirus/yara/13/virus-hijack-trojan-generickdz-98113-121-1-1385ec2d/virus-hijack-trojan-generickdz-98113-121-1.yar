rule Virus_Hijack_Trojan_GenericKDZ_98113_121_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_121_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02bf9031ebcf6d1a2c2139c03c7bc221fdda715d92a394e32e90c646cb425d67"

  strings:
    $s1 = "Drat$K" fullword ascii
    $s2 = "N;bEna:h" fullword ascii
    $s3 = "caRr,U&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}