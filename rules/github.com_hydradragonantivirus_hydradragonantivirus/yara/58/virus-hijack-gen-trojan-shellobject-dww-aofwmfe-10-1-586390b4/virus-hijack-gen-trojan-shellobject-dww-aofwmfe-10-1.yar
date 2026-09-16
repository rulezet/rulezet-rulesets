rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d93637472c19d6cd24cd2b8140edd0a37b966281457e5efeb49300d7e201944a"

  strings:
    $s1 = "Copyright 2014 AiosrdKofdr" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}