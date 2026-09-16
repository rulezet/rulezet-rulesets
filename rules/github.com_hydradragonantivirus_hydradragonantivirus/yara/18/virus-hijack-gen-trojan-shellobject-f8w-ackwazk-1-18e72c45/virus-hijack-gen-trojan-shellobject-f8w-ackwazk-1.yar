rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCkwazk_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCkwazk_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e87a3526305af95f614175185be83999cef4015093615443a601fe629d2cf8b8"

  strings:
    $s1 = "Jby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}