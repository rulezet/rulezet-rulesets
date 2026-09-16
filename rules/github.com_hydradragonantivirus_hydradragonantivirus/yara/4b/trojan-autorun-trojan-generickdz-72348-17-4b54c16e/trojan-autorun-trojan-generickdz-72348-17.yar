rule Trojan_Autorun_Trojan_GenericKDZ_72348_17 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c9e413ffe401cc058b60bb85adf529ebf04fcb5a81a3ab19c3d8893bb7764c4"

  strings:
    $s1 = "doob(^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}