rule Virus_Hijack_Trojan_GenericKDZ_105924_64_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_64_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7e10d8c805fd5343922e5ad6a74febf437b41df860a0da623a4d92fcd14da37"

  strings:
    $s1 = "SIAK;0b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}