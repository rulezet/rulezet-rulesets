rule Virus_Hijack_Trojan_GenericKDZ_105930_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b7c1d93addaec26d82c0b253418ebccb4cdf0124cb1559a524c3e9ea09664d9"

  strings:
    $s1 = "LUpE$b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}