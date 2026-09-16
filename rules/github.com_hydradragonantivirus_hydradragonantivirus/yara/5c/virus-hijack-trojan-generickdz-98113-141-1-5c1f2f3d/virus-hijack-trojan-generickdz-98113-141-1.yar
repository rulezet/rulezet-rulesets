rule Virus_Hijack_Trojan_GenericKDZ_98113_141_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_141_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c55153c70b39e0c2a1247c56e968cb8a6ba938dafc9a561058e4a7dbbf95d163"

  strings:
    $s1 = "LKJ>LAnk" fullword ascii
    $s2 = "b`}liiN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}