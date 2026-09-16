rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c99ae7e79b5e379b4e7197b983c91bfc1f34a204e9a77542a7dafae990fa315f"

  strings:
    $s1 = "}.What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}