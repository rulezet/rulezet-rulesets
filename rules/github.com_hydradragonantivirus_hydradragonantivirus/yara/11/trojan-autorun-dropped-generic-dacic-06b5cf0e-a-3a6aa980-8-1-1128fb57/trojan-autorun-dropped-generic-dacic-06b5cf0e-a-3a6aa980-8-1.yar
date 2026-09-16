rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_8_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78d13ea5697e1fb80680bc1f91c0f3ccb7f654fda3ef1becda50234e674cf49f"

  strings:
    $s1 = "L(aCOR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}