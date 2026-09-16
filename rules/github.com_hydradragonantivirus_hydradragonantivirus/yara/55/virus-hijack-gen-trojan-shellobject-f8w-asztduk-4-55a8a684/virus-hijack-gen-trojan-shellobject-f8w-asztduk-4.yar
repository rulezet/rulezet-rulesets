rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03cda7d0725ec73ecbbfeb73388e44cb18fc9bf023688bb6f93db7a02bd777bb"

  strings:
    $s1 = "j4or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}