rule Virus_Hooker_Trojan_GenericKD_48560802_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.GenericKD.48560802_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "747ae57c9ea864e545fdaebd9f90e94e53e24de0474c87b4d86daeafba1147f1"

  strings:
    $s1 = "trOG?7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}