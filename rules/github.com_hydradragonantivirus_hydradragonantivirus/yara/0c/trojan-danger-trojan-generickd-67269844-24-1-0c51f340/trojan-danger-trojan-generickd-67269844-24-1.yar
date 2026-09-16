rule Trojan_Danger_Trojan_GenericKD_67269844_24_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3381b0310329f2f5e78fd1bddc5ff96382549bc3a3f0a9455c6e0086ac6be7b0"

  strings:
    $s1 = "gUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}