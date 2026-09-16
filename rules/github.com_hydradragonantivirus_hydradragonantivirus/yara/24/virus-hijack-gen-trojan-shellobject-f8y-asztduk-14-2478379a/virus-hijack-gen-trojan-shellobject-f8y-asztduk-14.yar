rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ccc21fa3109bce73e2a67b416faaa11d887e735104f0543474c1ac30530d6c0"

  strings:
    $s1 = "J<or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}