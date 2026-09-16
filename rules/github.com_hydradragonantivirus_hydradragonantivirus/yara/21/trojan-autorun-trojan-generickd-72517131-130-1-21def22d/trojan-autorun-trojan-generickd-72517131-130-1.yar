rule Trojan_Autorun_Trojan_GenericKD_72517131_130_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_130_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7aaebda77d1831eb1d35e3c21fda06783e3db138007890ebbf37e950fe9d098"

  strings:
    $s1 = "bUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}