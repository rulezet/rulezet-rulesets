rule Trojan_Autorun_Trojan_GenericKDZ_94847_224_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_224_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20b740f2a24ef264efd0e7aa742ee93370ff21ce9a2c9a8c2a40d4ce0765791a"

  strings:
    $s1 = "]bAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}