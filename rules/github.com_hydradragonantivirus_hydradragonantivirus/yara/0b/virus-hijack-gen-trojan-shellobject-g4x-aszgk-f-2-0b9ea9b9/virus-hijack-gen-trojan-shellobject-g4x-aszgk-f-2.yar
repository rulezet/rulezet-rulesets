rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea7271522759d9033667c02f502bc3fe6374168d640492a11ea91a5d48b7cc86"

  strings:
    $s1 = "#Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}