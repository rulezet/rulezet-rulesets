rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf8380b0ef22ede54d99534bfdad4bcdd4350f31b3cf4f3bb680dc12f4ef02a3"

  strings:
    $s1 = "Reviewal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}