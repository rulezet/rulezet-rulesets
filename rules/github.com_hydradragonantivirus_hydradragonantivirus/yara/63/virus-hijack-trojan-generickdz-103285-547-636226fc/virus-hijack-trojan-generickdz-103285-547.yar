rule Virus_Hijack_Trojan_GenericKDZ_103285_547 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_547.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0f483c434a3a8c0d4c97a972a8427e1472ccb257c08d3a9e9ebd89ae6b94a55"

  strings:
    $s1 = "ujOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}