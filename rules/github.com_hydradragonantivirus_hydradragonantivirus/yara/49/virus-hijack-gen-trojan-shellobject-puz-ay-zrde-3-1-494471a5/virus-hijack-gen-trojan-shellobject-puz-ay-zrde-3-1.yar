rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_ay_ZRde_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@ay!ZRde_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b6fd7fdb923a5fd5185d7022470505a0fb1e4c9751bba8d54788775c7788f01"

  strings:
    $s1 = "SodA[\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}