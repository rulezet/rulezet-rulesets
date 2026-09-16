rule Trojan_Autorun_Trojan_GenericKD_64952004 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.64952004.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3d6309b8d1f753d1e108cbe4a2caf5ded00d06f57b75e81509958c57a5a0fe4"

  strings:
    $s1 = "?Unknown ex+" fullword ascii
    $s2 = "Qes@mEIo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}