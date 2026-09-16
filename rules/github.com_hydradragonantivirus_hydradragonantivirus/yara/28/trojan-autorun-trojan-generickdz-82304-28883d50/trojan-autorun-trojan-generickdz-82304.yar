rule Trojan_Autorun_Trojan_GenericKDZ_82304 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.82304.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b5e895ab304efac9d4b89dc60eea2c24f2d751107178c96c4aa1fe2d5680a5b"

  strings:
    $s1 = "~F$`mIRk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}