rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bfcf70c60987c5cfc062736c7654d45c4d38cba841bac343ef4728aa006ada1"

  strings:
    $s1 = "E-hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}