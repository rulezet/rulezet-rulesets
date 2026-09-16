rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_329_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_329_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5fb1240c38110559b131f1cdee05ad3f6882ac1630acbb0b9d6065a73d03c25"

  strings:
    $s1 = "infringement claim could have been avoided by`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}