rule Virus_Hijack_Trojan_GenericKDZ_103285_808 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_808.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf9c61167871f7144ed80e85de0d45bf46cf52f4d62a56a868761f8396178c69"

  strings:
    $s1 = "dmOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}