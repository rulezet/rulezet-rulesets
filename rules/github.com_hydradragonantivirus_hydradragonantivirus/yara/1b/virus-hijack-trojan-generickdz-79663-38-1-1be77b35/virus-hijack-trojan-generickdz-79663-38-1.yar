rule Virus_Hijack_Trojan_GenericKDZ_79663_38_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_38_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e4f45e4149652dae54c893d1cbdde8d9aede5a0471b696c0418b2d070326c69"

  strings:
    $s1 = "HOra!\\" fullword ascii
    $s2 = "RAgA(E?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}