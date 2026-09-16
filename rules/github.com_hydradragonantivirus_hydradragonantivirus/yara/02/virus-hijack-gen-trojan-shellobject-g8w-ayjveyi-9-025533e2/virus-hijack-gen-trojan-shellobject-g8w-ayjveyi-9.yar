rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a34773c5559a480a9250bca55100ae0ac4df7eef9b34a2f85a1e31c17ec2d09"

  strings:
    $s1 = ";gWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}