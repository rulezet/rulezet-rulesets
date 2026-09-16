rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e527f64dc7acd8562df531903b0b1ed4d496c095929e051a8dfbff4d26de7d93"

  strings:
    $s1 = "h[CIst" fullword ascii
    $s2 = "NOde,C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}