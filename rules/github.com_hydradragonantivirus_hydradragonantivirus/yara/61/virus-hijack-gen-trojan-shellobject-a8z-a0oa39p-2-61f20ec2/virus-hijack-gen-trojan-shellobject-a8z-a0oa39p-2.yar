rule Virus_Hijack_Gen_Trojan_ShellObject_A8Z_a0oa39p_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.A8Z@a0oa39p_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "934c2db3fa4340d38dfb5a748aaf96b14dcaf749135b257670e77bee3b00d0f4"

  strings:
    $s1 = "deb9ff4>i@jAnn<FqHrIvvDNyPzQ~~LV" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}