rule Virus_Hijack_Trojan_GenericKDZ_98388_189_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_189_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "893fc7ad3ab997ffecc20caa473af9eea1396a311383bea4a90c3200ed4a90ac"

  strings:
    $s1 = "!&wYde" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}