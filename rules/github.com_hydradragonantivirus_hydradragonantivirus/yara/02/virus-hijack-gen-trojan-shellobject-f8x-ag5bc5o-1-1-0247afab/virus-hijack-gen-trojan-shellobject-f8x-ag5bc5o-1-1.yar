rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd9830ceedaa996eac16dd8eb0901750a8b582a0469fc7cce5ccd8bfb9bce076"

  strings:
    $s1 = "Fneed dictionary" fullword ascii
    $s2 = "Encode;'" fullword ascii
    $s3 = "Simp#lepOb" fullword ascii
    $s4 = "Hogger" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}