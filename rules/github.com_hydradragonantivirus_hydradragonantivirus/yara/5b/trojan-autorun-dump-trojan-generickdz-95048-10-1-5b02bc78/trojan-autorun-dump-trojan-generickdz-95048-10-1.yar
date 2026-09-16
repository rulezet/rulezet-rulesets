rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_10_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ca16589b611b9387d3e631c1e60ac18e08477eb88dca3f0d9c31e8589cdadf6"

  strings:
    $s1 = "p&your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}