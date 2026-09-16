rule Virus_Hijack_Trojan_Peed_Gen_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7512d4bae7213c4287d6d5593659dbcee8bc93958d9e1ef901ebbf8933edf3b2"

  strings:
    $s1 = "=)YAiR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}