rule Virus_Hijack_Trojan_GenericKDZ_105924_176_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_176_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eff8a9248e6de459a685dba4e63872ac9c639021cb6438a36f62c1edae8cac4e"

  strings:
    $s1 = "Runtime error. Error number is P:%d L:%d." fullword ascii
    $s2 = "Error String is %s." fullword ascii
    $s3 = "MalloMem:%d (size)error!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}