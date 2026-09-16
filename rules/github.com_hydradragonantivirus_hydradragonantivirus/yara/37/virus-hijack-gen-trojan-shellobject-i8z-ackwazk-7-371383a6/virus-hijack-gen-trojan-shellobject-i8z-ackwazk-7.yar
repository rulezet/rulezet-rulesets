rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aCkwazk_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aCkwazk_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e17ce7132a46e350748099b9b6421f09f9a70ad7bd08dadd871b9683338c1ca"

  strings:
    $s1 = " by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}