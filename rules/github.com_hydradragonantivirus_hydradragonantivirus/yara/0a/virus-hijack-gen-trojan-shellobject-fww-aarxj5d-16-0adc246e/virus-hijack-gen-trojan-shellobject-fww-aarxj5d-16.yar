rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0ee226ccc3b8e2fb3c6cfe5923b11fe17c8c98389266175abbd90f0c1c2ae52"

  strings:
    $s1 = "sAmE}'[eu" fullword ascii
    $s2 = "AB U$r&Default" fullword ascii
    $s3 = "d0& \"Couldn't " fullword ascii
    $s4 = ",Handle" fullword ascii
    $s5 = ",ur%suld " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}