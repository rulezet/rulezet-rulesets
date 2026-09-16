rule Virus_Hijack_Trojan_GenericKDZ_105924_585_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_585_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8f39595ef382d5e7c38f131fb4a936119211f91a2e3916e49720f1af0cd1caa"

  strings:
    $s1 = "-7@pIty" fullword ascii
    $s2 = "/}BIRN" fullword ascii
    $s3 = "2}cLap" fullword ascii
    $s4 = "DEan<)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}