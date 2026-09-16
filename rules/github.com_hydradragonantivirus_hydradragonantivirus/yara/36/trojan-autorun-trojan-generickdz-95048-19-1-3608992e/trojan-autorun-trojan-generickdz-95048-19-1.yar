rule Trojan_Autorun_Trojan_GenericKDZ_95048_19_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "497cfc187c904da822128bca77c5d8874bd1b830a22ad1f950f7c43cdbc8d676"

  strings:
    $s1 = "Othat party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}