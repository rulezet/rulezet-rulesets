rule Trojan_Autorun_Trojan_GenericKDZ_94847_203_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_203_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "778ceae869b300ba56a5bef216fbae0836f3148e113092725bc4e80f3b53028c"

  strings:
    $s1 = ")orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}