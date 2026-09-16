rule Virus_Hijack_Trojan_GenericKDZ_103285_737_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_737_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d341516571aa397287981b2ac9767a3330d4d1b1552243f3d2f814141e71e369"

  strings:
    $s1 = "Adobe Photoshop3" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}