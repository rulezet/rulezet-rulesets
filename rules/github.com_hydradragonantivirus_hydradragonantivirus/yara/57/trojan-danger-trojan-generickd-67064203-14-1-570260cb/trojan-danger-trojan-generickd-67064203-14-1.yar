rule Trojan_Danger_Trojan_GenericKD_67064203_14_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67064203_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1a5bc8e0f1d23707193f2487c09104c08e69f51c8f9b1da065e3b2f811f14ca"

  strings:
    $s1 = "1Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}