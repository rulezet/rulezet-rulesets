rule Virus_Hijack_Trojan_GenericKDZ_103285_39 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_39.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9669765e083d501dd50c1049775b11c1c28b2e1eb2cea530ffdf2a91f0b1110e"

  strings:
    $s1 = "microsoft.com/office/backup. You may not distribute the backup copy of the so" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}