rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "132b4e55ab7051e356009027492d246d04afdc5e4c2a904b5ffc50508c2c3bab"

  strings:
    $s1 = "+or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}