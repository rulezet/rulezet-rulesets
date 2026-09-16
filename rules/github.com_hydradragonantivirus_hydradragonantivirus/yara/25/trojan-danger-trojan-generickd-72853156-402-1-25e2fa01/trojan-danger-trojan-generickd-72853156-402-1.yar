rule Trojan_Danger_Trojan_GenericKD_72853156_402_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_402_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73e54df9f48d1ebf6a3cd5565f05d142c447e6cdb2aa55621dcebfa917553d62"

  strings:
    $s1 = "?Unknown ex+" fullword ascii
    $s2 = "Qes@mEIo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}