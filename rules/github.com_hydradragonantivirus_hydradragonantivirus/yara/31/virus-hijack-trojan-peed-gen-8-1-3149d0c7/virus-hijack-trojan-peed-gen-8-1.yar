rule Virus_Hijack_Trojan_Peed_Gen_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51cdcfad583c42df21bdeb77a098873332dba9d81c9b2014c5a1e2a6a952ae89"

  strings:
    $s1 = "(wEel]" fullword ascii
    $s2 = "V\"swAt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}