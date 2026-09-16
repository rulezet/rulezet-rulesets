rule Virus_Hijack_Trojan_GenericKDZ_98113_420_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_420_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3924c1047f383fdbddcff3d3a1795e0e621fa1b39c17ef648216e14cd6c07e18"

  strings:
    $s1 = "R{wusT" fullword ascii
    $s2 = "typO,v" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}