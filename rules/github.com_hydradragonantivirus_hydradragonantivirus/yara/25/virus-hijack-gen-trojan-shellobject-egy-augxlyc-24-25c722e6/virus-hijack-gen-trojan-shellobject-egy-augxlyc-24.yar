rule Virus_Hijack_Gen_Trojan_ShellObject_eGY_augxLYc_24 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dba5740d6d1fd8b9d3cda004cbd8102c7a3f143d6096fd7b0a831e6793db932d"

  strings:
    $s1 = "/u_!kePi[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}