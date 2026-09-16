rule Virus_Hijack_Trojan_GenericKDZ_74550_39_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cd2b18b4e806c3acf9a60f92e823a8660cdf423c414856337db752e6c8fdd4c"

  strings:
    $s1 = "Beery>Hg" fullword ascii
    $s2 = "MeASe}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}