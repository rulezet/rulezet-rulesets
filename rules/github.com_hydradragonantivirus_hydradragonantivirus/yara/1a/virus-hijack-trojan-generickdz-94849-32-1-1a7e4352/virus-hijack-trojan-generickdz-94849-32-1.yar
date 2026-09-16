rule Virus_Hijack_Trojan_GenericKDZ_94849_32_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_32_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35bb1f7620e122370d7ebe3deeeff213932755fae065ffb2eafb2bc8d41e207d"

  strings:
    $s1 = "H C;woNt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}