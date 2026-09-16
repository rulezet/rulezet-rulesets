rule Virus_Hijack_Trojan_Peed_Gen_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a50ceee43d939962f0695fad34fb94ab97df93f60e3f31c87d538f6513260b5"

  strings:
    $s1 = "$maSK##" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}