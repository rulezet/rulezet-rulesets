rule Trojan_Danger_Trojan_GenericKD_67166905_252_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_252_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "640be0b444004ba2a475c41885778511187e7b499cf6f5870f6a9105f88102d6"

  strings:
    $s1 = "sOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}