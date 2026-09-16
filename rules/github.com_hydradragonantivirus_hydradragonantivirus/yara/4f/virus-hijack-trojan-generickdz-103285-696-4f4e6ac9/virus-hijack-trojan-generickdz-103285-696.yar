rule Virus_Hijack_Trojan_GenericKDZ_103285_696 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_696.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b78e5a85ab642e06d3bec8011e4420a134f65a853ed1d72dec3b02d8908d9f7"

  strings:
    $s1 = "~Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}