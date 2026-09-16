rule Virus_Hijack_Gen_Trojan_ShellObject_RAZ_aCEmdoo_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.RAZ@aCEmdoo_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdedb78d2886c5ef9c54279c9f7e8d65486d167bd98ffd9e79773e9c13cd944c"

  strings:
    $s1 = "bide}:>" fullword ascii
    $s2 = "Whoa>/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}