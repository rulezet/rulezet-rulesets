rule Virus_Hijack_Trojan_GenericKDZ_103285_666_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_666_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8acf5ce089a323ab4d09c794a136f7d459fb176a97e8dbe898a8972e1b830c7"

  strings:
    $s1 = "Adobe Photoshop3" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}