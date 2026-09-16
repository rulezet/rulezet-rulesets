rule Virus_Hijack_Trojan_GenericKDZ_74550_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17e049cdcd85bb75dbb180c079ae3fc464fce2d6aeeff31866f36974e795956f"

  strings:
    $s1 = "\"*dOPE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}