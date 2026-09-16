rule Virus_Danger_Gen_Trojan_ShellObject_g8X_aiHu4Wp {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.g8X@aiHu4Wp.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acdfedf106bc1a199170f3decaf32d0fd2c8c083c52757fcfc834b37b0b3b04b"

  strings:
    $s1 = "?What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}