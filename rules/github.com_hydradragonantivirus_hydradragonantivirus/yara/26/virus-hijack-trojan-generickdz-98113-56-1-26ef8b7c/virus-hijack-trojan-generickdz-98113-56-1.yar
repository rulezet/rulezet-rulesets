rule Virus_Hijack_Trojan_GenericKDZ_98113_56_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_56_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97804fd62c596e08d6c6d2c52bbcfe57d10dbaefa3343205ed2d63c81d9a1ea6"

  strings:
    $s1 = "lAud'A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}