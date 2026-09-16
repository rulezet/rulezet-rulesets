rule Virus_Hijack_Trojan_GenericKDZ_105924_426_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_426_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b6d73bce5be82f30db4933785c724bd74cc8ef66a871471ea0dbc5e50e6a515"

  strings:
    $s1 = "TALma>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}