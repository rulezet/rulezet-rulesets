rule Virus_Hijack_Gen_Trojan_ShellObject_wSZ_a8YIsUn_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a8YIsUn_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "801013208badc834d98564329c79a7ae378b30728ce754da3ae925c262c6e93c"

  strings:
    $s1 = "^remainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}