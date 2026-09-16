rule Virus_Hijack_Trojan_GenericKDZ_105930_31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c34f5f1cf4c4f45470892c221b4a46721e97f12ad85916a29f5d62449dd0e16"

  strings:
    $s1 = "ELmy$4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}