rule VirusShareTrojanDownLoader4344429_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4344429_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f40ca038a9742a9c780d97830e04ca605e9440fae37267ddc84b3b5c0b09c0c0"

  strings:
    $s1 = "6Simp=?Memory" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}