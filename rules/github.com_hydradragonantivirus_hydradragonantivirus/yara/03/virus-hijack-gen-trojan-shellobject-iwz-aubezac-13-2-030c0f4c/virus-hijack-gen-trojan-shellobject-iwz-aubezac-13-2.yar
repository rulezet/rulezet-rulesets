rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aae4a388977ac746978ada2f742be026cbea20c44d54b4ef09d5e981e4f6ae0c"

  strings:
    $s1 = "[]daDo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}