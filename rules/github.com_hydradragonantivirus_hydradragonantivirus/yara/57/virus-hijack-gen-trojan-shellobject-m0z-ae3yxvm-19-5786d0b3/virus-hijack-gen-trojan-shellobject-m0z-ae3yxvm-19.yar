rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95c03163c6072754008a0b96927afccb8b042951374bab1ea4a47e2212d220b3"

  strings:
    $s1 = "*'4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}