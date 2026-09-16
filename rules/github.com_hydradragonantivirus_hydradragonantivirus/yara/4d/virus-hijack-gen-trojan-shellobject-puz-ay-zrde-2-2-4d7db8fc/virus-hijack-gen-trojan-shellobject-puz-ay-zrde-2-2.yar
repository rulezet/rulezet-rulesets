rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_ay_ZRde_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@ay!ZRde_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b3e5ce4ed33977d3debc5c8baa2d0b6f3b704e80380a9334349a5859a10800d"

  strings:
    $s1 = "n#welK" fullword ascii
    $s2 = "':deRe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}