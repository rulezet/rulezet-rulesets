rule Trojan_Autorun_Trojan_GenericKD_72250432_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72250432_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8343f68bd76278396d9d0c5c8e45b60783283efde65c6634ee4b90d42868ef56"

  strings:
    $s1 = "rZhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}