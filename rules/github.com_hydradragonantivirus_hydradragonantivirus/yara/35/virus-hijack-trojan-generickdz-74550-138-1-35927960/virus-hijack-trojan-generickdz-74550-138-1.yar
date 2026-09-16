rule Virus_Hijack_Trojan_GenericKDZ_74550_138_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_138_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "243c74d772d8a97b50ebe6f955a45ff7f1f485e83df5c40fab2abde9ee2994f0"

  strings:
    $s1 = "-z&)REIn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}