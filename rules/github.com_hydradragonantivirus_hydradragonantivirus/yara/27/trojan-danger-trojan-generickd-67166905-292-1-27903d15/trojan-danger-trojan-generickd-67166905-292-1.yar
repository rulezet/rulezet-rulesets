rule Trojan_Danger_Trojan_GenericKD_67166905_292_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_292_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2ed1e88a193d514dee8d79fd492d70dd7b64cf35c3cb4056048b01def5d44c2"

  strings:
    $s1 = "tOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}