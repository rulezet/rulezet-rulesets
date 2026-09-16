rule VirusShareTrojanDridex646_20_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDridex646_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cf83a0e4f4d869703f3cebabfe4ffd5e8e47bfca1c9d4e041566b10d90f219f"

  strings:
    $s1 = "Gameness" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}