rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "186558b6f6fd3f0e75dabf2a88ff5e838cb684004ceb9b1d2850227c8f83bbc5"

  strings:
    $s1 = "&by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}