rule Virus_Hijack_Trojan_GenericKDZ_98113_238_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_238_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b5a22cb5287d178d0fcf79927406c644cc626fb9cf53ca1aecf4c404ec2e032"

  strings:
    $s1 = "4{STUg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}