rule Trojan_Danger_Trojan_GenericKD_72853156_186_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_186_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b56f0609466facbfa521d82d30a351dd4d14f5fcf01e0a4817bfcbd68e717e77"

  strings:
    $s1 = "Copyright (C) biydtfrer" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}