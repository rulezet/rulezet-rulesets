rule Virus_Hijack_Trojan_GenericKDZ_98388_115_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_115_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7f7796c7a8831803428711fade231d93e0555fc922d8bfb8016b8114de7bca4"

  strings:
    $s1 = "gv>BiTO" fullword ascii
    $s2 = "AGroM#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}