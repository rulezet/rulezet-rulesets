rule Trojan_Danger_Trojan_GenericKD_67166905_481_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_481_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a135a90a91fec048aee99a6b5150934bb3dbddfc3c3f5a09985c0888984f90b8"

  strings:
    $s1 = "bOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}