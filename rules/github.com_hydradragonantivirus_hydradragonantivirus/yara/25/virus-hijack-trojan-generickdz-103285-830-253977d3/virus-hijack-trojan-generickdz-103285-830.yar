rule Virus_Hijack_Trojan_GenericKDZ_103285_830 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_830.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe876d9be4d79fbd93a5e86f89c52a302145c9988b3055882238992436d5f03e"

  strings:
    $s1 = "yCOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}