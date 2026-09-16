rule Virus_Infector_Trojan_GenericKD_33222094_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.GenericKD.33222094_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87e723f1007aff9de2b350ce8e6feecb905b47a24868d30b871adc04ed55388d"

  strings:
    $s1 = "!ThisRprogram cannot be run in DOS more." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}