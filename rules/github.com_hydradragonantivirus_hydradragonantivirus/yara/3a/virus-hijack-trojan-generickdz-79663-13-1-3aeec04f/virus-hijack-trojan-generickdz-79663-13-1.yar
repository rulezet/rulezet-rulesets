rule Virus_Hijack_Trojan_GenericKDZ_79663_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec11f32932416aba952c3c0d938cc1324c20cef36ed186b01140a3ad039f9ea"

  strings:
    $s1 = "twit'@" fullword ascii
    $s2 = "tb<SeAL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}