rule Trojan_Danger_Trojan_GenericKD_67166905_311 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_311.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8817c43a8c121d64f31f03908fb77204eca2a284e547757f48e2a94c181be806"

  strings:
    $s1 = "V[TRap?<RRRRRRRRRRna" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}