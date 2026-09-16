rule Trojan_Danger_Trojan_GenericKD_67166905_479_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_479_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6678737f433f88fa149571b636dfeb78f554a2e4273256a283f70e52da23d75b"

  strings:
    $s1 = "Npolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii
    $s2 = "If you have a dispute with Oracle or if you wish to provide a notice under the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}