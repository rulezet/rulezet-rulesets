rule Virus_Danger_Gen_Trojan_ShellObject_g8X_aCMzZah_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.g8X@aCMzZah_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "258fb447b94a76da42da0c4d7d187bb33ddf377b161ad4793512bdf2388f901b"

  strings:
    $s1 = "Interactive Ruby.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}