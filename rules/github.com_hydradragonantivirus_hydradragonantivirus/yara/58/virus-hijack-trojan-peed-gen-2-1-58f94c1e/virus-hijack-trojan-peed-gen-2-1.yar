rule Virus_Hijack_Trojan_Peed_Gen_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "318e9467de91762332ecf0b15937555b49d02b328ace3c400e6a37b43c2d80c5"

  strings:
    $s1 = "ogum}W" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}