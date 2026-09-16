rule Virus_Hijack_Trojan_GenericKDZ_98113_305 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_305.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b22f2c902694dfc47694334197596f0bb519803a5fc62778e7edbb8fc61c048"

  strings:
    $s1 = "f\"by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}