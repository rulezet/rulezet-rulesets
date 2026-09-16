rule Virus_Hijack_Trojan_Peed_Gen_72 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_72.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eca5274ab7f44e42522677bd2b080e8c9ab153ead29228af732646ee9700bbff"

  strings:
    $s1 = "8*soDy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}