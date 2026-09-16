rule VirusShareTrojanPWSSiggen34304 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSSiggen34304.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "083dbc12b101020fc3a3391de52133589d2d07eeb526e9d6fb7e8452b326119f"

  strings:
    $s1 = "[IDES&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}