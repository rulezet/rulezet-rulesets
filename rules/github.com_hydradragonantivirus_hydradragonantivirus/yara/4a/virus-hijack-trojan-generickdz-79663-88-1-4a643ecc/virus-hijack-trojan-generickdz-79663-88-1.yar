rule Virus_Hijack_Trojan_GenericKDZ_79663_88_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_88_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1b5ab69ee3022713a0a5cbb60e54fd14a8fcc112ba03e348e9f83a6647255cc"

  strings:
    $s1 = "SoLa$[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}