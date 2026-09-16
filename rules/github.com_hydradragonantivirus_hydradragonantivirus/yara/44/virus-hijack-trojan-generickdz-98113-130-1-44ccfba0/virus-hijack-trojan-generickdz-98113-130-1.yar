rule Virus_Hijack_Trojan_GenericKDZ_98113_130_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_130_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c155d3b63b016c286b2cbbca9cd5812ea8758561775924c5eba85624d99de8f"

  strings:
    $s1 = "pcffI>BOOl" fullword ascii
    $s2 = "JeLL?B" fullword ascii
    $s3 = "k?piRN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}