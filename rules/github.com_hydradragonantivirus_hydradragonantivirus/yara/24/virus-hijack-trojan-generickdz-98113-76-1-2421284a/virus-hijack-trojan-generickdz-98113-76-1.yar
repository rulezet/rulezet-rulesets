rule Virus_Hijack_Trojan_GenericKDZ_98113_76_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_76_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abf34fdddbe98f158f84191c896bd4ca55e5fb4fb1eff09353b250d5a076cd90"

  strings:
    $s1 = "hUsh%H" fullword ascii
    $s2 = "JAKo)&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}