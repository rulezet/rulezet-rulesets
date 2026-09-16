rule Trojan_Autorun_Trojan_GenericKD_72254740_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72254740_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffdd0d6e85d8c3bf3634fe366d732741c98d211c5601cfd8c4b05a3306bec831"

  strings:
    $s1 = "pUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}