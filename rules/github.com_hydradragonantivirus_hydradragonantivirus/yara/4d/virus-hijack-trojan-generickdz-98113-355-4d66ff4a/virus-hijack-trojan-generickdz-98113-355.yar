rule Virus_Hijack_Trojan_GenericKDZ_98113_355 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_355.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02a322d9bb2c948dd8a963a11be274d30cb769e69316c82bd95799c0fdb6c7e0"

  strings:
    $s1 = "Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data,`" fullword ascii
    $s2 = ":assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}