rule Trojan_Autorun_Trojan_GenericKDZ_95048_25 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c310525564cf6f52fe2c1d3a5a9f678393c25a864619253163cf264dad172598"

  strings:
    $s1 = "@j<orAD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}