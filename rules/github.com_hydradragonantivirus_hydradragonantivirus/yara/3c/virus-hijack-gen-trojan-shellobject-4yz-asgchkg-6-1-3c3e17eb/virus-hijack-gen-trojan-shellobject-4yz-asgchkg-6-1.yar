rule Virus_Hijack_Gen_Trojan_ShellObject_4yZ_aSgChKg_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.4yZ@aSgChKg_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4055a428c9f7f35e7466eb1942299d2c83262c90feec451446a21c09114e1c57"

  strings:
    $s1 = "gram Files\\(7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}