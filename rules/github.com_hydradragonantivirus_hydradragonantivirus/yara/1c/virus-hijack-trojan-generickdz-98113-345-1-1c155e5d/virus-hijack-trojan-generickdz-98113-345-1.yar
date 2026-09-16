rule Virus_Hijack_Trojan_GenericKDZ_98113_345_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_345_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5d6f2a28014782a35f1d148f191faa9360ce8d90440a3f5e8156dc14eac85f2"

  strings:
    $s1 = "sElL]mQ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}