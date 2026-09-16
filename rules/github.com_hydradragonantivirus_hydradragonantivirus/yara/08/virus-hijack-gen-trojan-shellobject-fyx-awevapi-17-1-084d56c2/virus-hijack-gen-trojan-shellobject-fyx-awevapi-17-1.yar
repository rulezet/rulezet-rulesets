rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f390a11c8c293164b86c6656f76ca9c34933124f232f804620c54b51abfbeecf"

  strings:
    $s1 = "File is invalid." fullword wide
    $s2 = "Java(TM) Platform SE U21" fullword wide
    $s3 = "Text}@" fullword ascii
    $s4 = "Oracle America Inc." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}