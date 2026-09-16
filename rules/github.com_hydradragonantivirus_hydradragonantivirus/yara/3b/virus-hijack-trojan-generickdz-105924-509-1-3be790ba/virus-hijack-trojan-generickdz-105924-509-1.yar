rule Virus_Hijack_Trojan_GenericKDZ_105924_509_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_509_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2875ef970abec183257140bb6ea70f8dc889f45eeedb651e98fb08780621a72f"

  strings:
    $s1 = "SEta j" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}