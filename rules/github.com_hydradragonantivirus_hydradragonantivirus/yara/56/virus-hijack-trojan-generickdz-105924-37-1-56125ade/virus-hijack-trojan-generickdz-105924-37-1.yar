rule Virus_Hijack_Trojan_GenericKDZ_105924_37_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb255276441934648d36fbb8d6651a12ebacad8f2ea115b7e0dd13bbed8e27e4"

  strings:
    $s1 = "DASi?G" fullword ascii
    $s2 = "d< LuBe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}