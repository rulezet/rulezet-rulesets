rule Trojan_Autorun_Trojan_GenericKD_72517131_168_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_168_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9d9d496c4f6513f836793c5ec56de280c1ab35bec645cdbfd84efe742aaf2cb"

  strings:
    $s1 = "required and all actual users must be license" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}