rule Virus_Hijack_Trojan_GenericKDZ_105924_415_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_415_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "576767ec753d40e9eeb7330cdd6af47c58776c1156ddf62866a837fea927eca9"

  strings:
    $s1 = "}([[Sump" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}