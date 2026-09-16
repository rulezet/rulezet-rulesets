rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aCMzZah {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aCMzZah.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8db14f4f32144761a2562b97d95888c00702fe934859e157e231f2ca42bea6ea"

  strings:
    $s1 = "Zorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}