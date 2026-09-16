rule Trojan_Sysbot_Trojan_SalityStub_F_18 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.SalityStub.F_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4b214c88c570f1922ca0732fb8a7a32b3ca59f9299295cdfd880b19e707c074"

  strings:
    $s1 = "bikh`\\}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}