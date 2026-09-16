rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_a0a9m9p_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@a0a9m9p_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b9cfeec00fe1526f86f5115a2a170d7a9c50bd974b1ba68bdefa64228825545"

  strings:
    $s1 = "8Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}