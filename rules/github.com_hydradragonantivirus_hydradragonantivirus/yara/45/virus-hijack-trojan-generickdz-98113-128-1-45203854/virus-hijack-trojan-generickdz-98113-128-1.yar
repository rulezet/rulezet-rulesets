rule Virus_Hijack_Trojan_GenericKDZ_98113_128_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_128_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e9d99bbf0b4172b51812894eb2c3db18a5ae8a0c611276b42d73438e79e5a60"

  strings:
    $s1 = "[kaiD?F" fullword ascii
    $s2 = "el\"sEIt" fullword ascii
    $s3 = "Corn(+" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}