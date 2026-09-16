rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCXl7mh_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cf87d40e3c99a58cc472a288430921f511410dae0ad6e2d4c3ff4de8f4ac29c"

  strings:
    $s1 = "!Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}