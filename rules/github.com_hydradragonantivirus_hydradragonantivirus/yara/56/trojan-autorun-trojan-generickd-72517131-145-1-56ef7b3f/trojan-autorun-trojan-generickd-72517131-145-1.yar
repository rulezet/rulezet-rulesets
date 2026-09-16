rule Trojan_Autorun_Trojan_GenericKD_72517131_145_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_145_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "508fa808fb4966d7e8fc8d556320b4ebc7d48b8fd800bead1fb3839bb413f642"

  strings:
    $s1 = "8User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}