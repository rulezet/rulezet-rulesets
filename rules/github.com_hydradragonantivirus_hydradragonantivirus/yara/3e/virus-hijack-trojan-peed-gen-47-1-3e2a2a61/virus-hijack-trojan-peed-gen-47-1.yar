rule Virus_Hijack_Trojan_Peed_Gen_47_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_47_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "372fa7c3b44df94cc11f7accbffdd5b3ae434b3b7daf2049624b0865d81cb8ae"

  strings:
    $s1 = "#3P_!tREE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}