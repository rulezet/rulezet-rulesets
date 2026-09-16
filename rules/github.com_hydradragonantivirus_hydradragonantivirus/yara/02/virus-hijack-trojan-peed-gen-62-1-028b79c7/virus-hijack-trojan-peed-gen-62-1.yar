rule Virus_Hijack_Trojan_Peed_Gen_62_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_62_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8247f9e88d6a5c81bdcbaf5815a666902bfcb5cefdb2677486adbe6e7bf5bbaf"

  strings:
    $s1 = "(RiCeY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}