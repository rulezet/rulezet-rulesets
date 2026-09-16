rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aCEmdoo_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aCEmdoo_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "352de7a343d88ad526b090593733b10c5ab597a26046052b91ebf3d547de5236"

  strings:
    $s1 = "?$SifT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}