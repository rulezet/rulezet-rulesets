rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41d9285e6ec20f5064ad055edeff4f6d17c1616bbf0368f25ae9ceddec162aa1"

  strings:
    $s1 = "!tor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}