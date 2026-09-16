rule Virus_Hijack_Trojan_PWS_Banker_FMA_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.PWS.Banker.FMA_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b406ae26e5ad581a0ef70b9b2cfa84d24fde617d5e6849ff39bcb459142c81a"

  strings:
    $s1 = "95V`CHAL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}