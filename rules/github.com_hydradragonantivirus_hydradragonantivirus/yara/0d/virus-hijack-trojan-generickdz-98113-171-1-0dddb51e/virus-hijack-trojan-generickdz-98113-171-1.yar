rule Virus_Hijack_Trojan_GenericKDZ_98113_171_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_171_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91fce1d8b19844172edd5596876300327c25eb024faef8ad44b79d326b140720"

  strings:
    $s1 = "CLAM&1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}