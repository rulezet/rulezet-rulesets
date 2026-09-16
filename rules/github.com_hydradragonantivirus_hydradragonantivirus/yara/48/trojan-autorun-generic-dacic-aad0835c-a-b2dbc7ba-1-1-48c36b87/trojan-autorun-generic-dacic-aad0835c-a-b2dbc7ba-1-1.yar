rule Trojan_Autorun_Generic_Dacic_AAD0835C_A_B2DBC7BA_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.AAD0835C.A.B2DBC7BA_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52a8342a2a32e4060f11f56c84b9ac06d95c0e05a9949306cfddf1a3315b94e4"

  strings:
    $s1 = "'by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}