rule Virus_Hijack_Trojan_GenericKDZ_99416_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85dd67e6f149f8d59669e7413cf5d57de8e2d2456af3b5cdd0adde5288131703"

  strings:
    $s1 = "PUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}