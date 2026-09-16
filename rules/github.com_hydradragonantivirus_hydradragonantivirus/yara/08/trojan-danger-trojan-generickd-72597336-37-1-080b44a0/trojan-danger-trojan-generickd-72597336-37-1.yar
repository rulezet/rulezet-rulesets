rule Trojan_Danger_Trojan_GenericKD_72597336_37_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72597336_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd2ff95812e3e91d66fbc31df4ce42a731ddfb222e450beb7054da3c1b2896b0"

  strings:
    $s1 = "!purchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}