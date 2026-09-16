rule VirusShareTrojanClipper50 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanClipper50.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3abd920228d06f2019f40795201496bdded17f82750a175db74ae8f2b9640119"

  strings:
    $s1 = "Rich;G" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}