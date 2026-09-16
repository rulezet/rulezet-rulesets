rule Virus_Hijack_Trojan_GenericKDZ_74550_213_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_213_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17bc3bd9cd7d81c5caf7dc98656e31b1a7836de9d4b3ba7a9f9b8245ec44bdd7"

  strings:
    $s1 = "sION|;5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}