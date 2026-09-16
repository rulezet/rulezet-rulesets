rule Virus_Hooker_Trojan_Generic_30984256_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.Generic.30984256_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d46185a9058e18fae3efea5afcf687b4534713db920f7b5d42890ed358486063"

  strings:
    $s1 = "|\\(WheT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}