rule Virus_Hijack_Dropped_Trojan_Peed_Gen_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Trojan.Peed.Gen_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5b34f1ad8cda545b6e0da392d2739cd63f249b0682f14918051f8fecae659a0"

  strings:
    $s1 = "a[adad" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}