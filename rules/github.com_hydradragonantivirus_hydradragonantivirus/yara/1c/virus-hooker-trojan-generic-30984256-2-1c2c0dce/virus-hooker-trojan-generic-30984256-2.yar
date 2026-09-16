rule Virus_Hooker_Trojan_Generic_30984256_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.Generic.30984256_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84ab0ddc06f38d3570ae4ffc71dc96d11b44d611b5f63b946ae247c04085c713"

  strings:
    $s1 = "|\\(WheT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}