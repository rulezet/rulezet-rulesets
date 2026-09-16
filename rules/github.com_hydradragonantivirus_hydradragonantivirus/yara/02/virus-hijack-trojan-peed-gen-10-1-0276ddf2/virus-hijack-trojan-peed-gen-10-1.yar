rule Virus_Hijack_Trojan_Peed_Gen_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0347c90d28faf7be535bbf416b6a5e5e17c6c8834199096672757b0b049681d7"

  strings:
    $s1 = "`AnSU{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}