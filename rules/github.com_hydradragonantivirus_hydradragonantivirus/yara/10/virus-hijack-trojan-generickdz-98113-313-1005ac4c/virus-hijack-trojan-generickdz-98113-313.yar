rule Virus_Hijack_Trojan_GenericKDZ_98113_313 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_313.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d848e39c6947cfd79f6245bd01187e7024d3c9570d30399f1552df721483399"

  strings:
    $s1 = "%C  kNIt>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}