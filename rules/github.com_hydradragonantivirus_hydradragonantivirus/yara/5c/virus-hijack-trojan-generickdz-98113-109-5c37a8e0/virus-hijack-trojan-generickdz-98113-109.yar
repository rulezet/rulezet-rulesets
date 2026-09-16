rule Virus_Hijack_Trojan_GenericKDZ_98113_109 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_109.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "852ad1959209b4a4243f5a54a5ab453e8d041d429f9a701e1250e36a34a4b945"

  strings:
    $s1 = "@by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}