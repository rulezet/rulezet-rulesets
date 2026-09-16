rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_35_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3e9d83dc4f13e33c20dc571fda38323d426d2e4739f19d01565f4dc8aaa88d4"

  strings:
    $s1 = "Enravish" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}