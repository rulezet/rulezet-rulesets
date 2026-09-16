rule Virus_Danger_Trojan_GenericKDZ_105921 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.105921.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4656b9d94550aef053757d2fc547c0a5f747847d5e9cff2222745ef188889acf"

  strings:
    $s1 = "*@2013 software. For your convenience, we" fullword ascii
    $s2 = "dITe%!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}