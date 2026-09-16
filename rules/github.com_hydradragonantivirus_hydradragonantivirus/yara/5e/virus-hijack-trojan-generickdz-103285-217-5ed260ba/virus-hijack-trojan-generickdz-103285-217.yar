rule Virus_Hijack_Trojan_GenericKDZ_103285_217 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_217.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1970e97e20c6bd1b3197d7d185bcb2cf1919700dbe7100413c8f93ca5cf96d4c"

  strings:
    $s1 = "5Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}