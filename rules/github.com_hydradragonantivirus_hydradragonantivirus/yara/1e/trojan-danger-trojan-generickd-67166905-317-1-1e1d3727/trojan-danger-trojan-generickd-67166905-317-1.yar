rule Trojan_Danger_Trojan_GenericKD_67166905_317_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_317_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e09b11a02a999fc4e0f55e5da8f1543df2e5b55d25054ff00038d7ef9deda3f9"

  strings:
    $s1 = "0Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}