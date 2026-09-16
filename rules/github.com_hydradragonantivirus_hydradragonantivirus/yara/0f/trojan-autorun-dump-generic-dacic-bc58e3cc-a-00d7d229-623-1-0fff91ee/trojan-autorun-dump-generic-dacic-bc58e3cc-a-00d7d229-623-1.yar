rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_623_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_623_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6f139de1567f605dacea980a18f3ee79d51ca3f64d1388777061dd3f0c6099f"

  strings:
    $s1 = "~^Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}