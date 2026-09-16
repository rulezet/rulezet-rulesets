rule Virus_Hijack_Trojan_GenericKDZ_79663_34_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c879ecf35579c79848ec0acc496c8d26284c3fc7aadd547d92d006a396e5eda"

  strings:
    $s1 = "WHiT&h" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}