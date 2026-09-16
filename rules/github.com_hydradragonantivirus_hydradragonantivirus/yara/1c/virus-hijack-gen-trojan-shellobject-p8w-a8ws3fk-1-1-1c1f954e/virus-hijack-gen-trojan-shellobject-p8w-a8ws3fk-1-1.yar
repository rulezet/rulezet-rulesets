rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_a8ws3Fk_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@a8ws3Fk_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "645a2ff734c93a88502014b81074f433034c5669ed24d707290425b416a254d3"

  strings:
    $s1 = "Runtime Check, Version 1.0" fullword wide
    $s2 = "Runtime Check" fullword wide
    $s3 = "About Installer" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}