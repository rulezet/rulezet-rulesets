rule Virus_Hijack_Trojan_GenericKDZ_79663_74_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_74_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e226b3455df29182ce27ceb96cc88b5027c0674c0b9a9f05044f41a46ea8cc"

  strings:
    $s1 = "mARU;;P!J~Z'" fullword ascii
    $s2 = "p*bAtZ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}