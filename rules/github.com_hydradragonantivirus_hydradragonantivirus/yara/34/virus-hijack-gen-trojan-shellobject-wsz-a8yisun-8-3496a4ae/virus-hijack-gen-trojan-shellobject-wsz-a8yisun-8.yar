rule Virus_Hijack_Gen_Trojan_ShellObject_wSZ_a8YIsUn_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a8YIsUn_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eceb3ca12fd479be97bac46055b8cf6651bf367a6aedf0cfb82e6eafa92a2ec1"

  strings:
    $s1 = "%Iremainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}