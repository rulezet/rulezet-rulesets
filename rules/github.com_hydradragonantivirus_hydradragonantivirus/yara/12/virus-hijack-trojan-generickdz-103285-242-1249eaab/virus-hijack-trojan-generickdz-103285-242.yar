rule Virus_Hijack_Trojan_GenericKDZ_103285_242 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_242.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68490142c2f45fd1683f797655119dd8f29b8a265cdc8d522a7c78a5e8f53a4f"

  strings:
    $s1 = "ROracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}