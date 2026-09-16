rule Virus_Hijack_Trojan_GenericKDZ_74550_53_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_53_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adabdcafad7004bc1e7879c12ecf5bec98bbd0f1c1379e4aa72c725183ed814e"

  strings:
    $s1 = "=]TaDE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}