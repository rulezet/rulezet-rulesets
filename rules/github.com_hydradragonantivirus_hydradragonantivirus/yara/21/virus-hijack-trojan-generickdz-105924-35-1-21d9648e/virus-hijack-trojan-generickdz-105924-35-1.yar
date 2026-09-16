rule Virus_Hijack_Trojan_GenericKDZ_105924_35_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85cc96c900f78d4352dcff39793a7a1a54eaa363abada2e902a38b0011ffa841"

  strings:
    $s1 = "fg+;#OdOr" fullword ascii
    $s2 = "42%emIT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}