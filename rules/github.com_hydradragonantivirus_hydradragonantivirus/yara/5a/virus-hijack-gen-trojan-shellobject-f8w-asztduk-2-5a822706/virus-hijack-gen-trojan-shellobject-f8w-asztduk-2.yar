rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19d85608a24f4e54fc3cb0221299b8b2c348c67f0b2eb324a47b0e1797e01f56"

  strings:
    $s1 = "3or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}