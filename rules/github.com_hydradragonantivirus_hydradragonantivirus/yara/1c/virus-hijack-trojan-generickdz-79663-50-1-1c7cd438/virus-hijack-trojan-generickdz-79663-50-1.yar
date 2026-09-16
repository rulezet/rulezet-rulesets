rule Virus_Hijack_Trojan_GenericKDZ_79663_50_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_50_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57ef867310f8af96fb351c613df339b241c10bba94677bcf4ebe2e5ec952b756"

  strings:
    $s1 = "-?LooN" fullword ascii
    $s2 = "Bw#0 MOOP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}