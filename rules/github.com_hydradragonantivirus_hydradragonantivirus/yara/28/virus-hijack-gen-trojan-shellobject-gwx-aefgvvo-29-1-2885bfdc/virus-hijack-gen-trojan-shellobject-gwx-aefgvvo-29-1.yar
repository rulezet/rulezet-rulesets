rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93b681543d26b564ddac9746b3f8747921bd3a21853ef191d2f503a1264de42d"

  strings:
    $s1 = "Cubhood" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}