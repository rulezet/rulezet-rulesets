rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_84_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_84_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cf8636620f1e8af399861a624184ad71168d7e4ce65954f4c52c73bb6f9d98f"

  strings:
    $s1 = "1@cOmB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}