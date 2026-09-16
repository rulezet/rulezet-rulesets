rule Virus_Hijack_Trojan_Peed_Gen_28 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44feffa3f7e9f8c8d42d5683ec06d9b3cc4e108ea665b8dc2f7af339c6bf087f"

  strings:
    $s1 = "&lH<raSh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}