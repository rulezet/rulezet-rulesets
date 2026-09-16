rule Virus_Hijack_Trojan_GenericKDZ_105924_606_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_606_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eee2f636b7d9b76e2e59987f1cc7e1c6cbe35453cda9c3a38ae950cba9e36b21"

  strings:
    $s1 = "T`peCH" fullword ascii
    $s2 = "fqy#)LilE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}