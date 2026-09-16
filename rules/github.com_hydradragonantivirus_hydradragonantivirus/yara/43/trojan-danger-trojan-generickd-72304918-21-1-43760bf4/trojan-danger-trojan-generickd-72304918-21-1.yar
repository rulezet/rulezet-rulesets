rule Trojan_Danger_Trojan_GenericKD_72304918_21_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec5cabb2ad2ffc41074d509d3665c336828fb76aa7a66a6a62e3186aecf3285b"

  strings:
    $s1 = "^a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}