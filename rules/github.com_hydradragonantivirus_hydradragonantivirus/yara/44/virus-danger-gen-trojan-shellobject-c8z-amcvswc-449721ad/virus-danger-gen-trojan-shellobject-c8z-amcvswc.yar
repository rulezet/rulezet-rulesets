rule Virus_Danger_Gen_Trojan_ShellObject_C8Z_amCvSwc {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.C8Z@amCvSwc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48fcafe9d10b6548471ddb518746b5a11b11e294328668dcc5c762b77d7834f1"

  strings:
    $s1 = "}University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}