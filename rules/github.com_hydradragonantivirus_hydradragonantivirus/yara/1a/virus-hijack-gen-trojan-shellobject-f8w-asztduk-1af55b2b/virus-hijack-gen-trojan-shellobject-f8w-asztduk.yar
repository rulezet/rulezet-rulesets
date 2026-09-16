rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3ab7d44f1e2a39a941fcc2b53286ab31b891fd384a86e42f5493eb2c7cf2ffe"

  strings:
    $s1 = "wPor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}