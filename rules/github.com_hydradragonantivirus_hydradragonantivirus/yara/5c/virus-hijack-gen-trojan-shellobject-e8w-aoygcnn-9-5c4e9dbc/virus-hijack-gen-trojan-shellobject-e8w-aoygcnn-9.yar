rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "536dcaef28448e83bbcfbd535a352b3b19e3264dc62ff0823fc85d2553831df6"

  strings:
    $s1 = "mhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}