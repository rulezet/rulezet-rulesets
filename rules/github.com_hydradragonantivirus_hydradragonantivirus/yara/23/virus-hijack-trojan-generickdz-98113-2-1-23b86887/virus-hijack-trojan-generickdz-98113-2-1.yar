rule Virus_Hijack_Trojan_GenericKDZ_98113_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b00749c72220273ca1ad136fa18f00e6628059abe66c5411b4aa532ba03f1db"

  strings:
    $s1 = "hAYz$*," fullword ascii
    $s2 = "AdAw{/;" fullword ascii
    $s3 = "p$;>feAT" fullword ascii
    $s4 = "?]pizE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}