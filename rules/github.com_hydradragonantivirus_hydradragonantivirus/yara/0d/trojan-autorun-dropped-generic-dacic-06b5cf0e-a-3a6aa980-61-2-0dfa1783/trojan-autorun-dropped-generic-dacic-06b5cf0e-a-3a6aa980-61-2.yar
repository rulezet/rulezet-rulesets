rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_61_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_61_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bd9852faaa9bdf51cef768e3f23419ba8b2895344d2e9ce50726c75aeb65347"

  strings:
    $s1 = "gaLl)D" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}