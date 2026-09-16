rule Virus_Hijack_Gen_Trojan_ShellObject_BuZ_amBwvTb_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.BuZ@amBwvTb_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "add4c74f0c8403d7b70da6ff9d80d53cdaefe265bdcaf5beef05e2c3db62c333"

  strings:
    $s1 = "rEcCy?_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}