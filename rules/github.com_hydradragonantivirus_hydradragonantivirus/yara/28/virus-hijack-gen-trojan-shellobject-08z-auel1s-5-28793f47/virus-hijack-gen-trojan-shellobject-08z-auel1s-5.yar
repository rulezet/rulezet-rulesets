rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_auel1S_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@auel1S_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3df79ea41e5ee048e611214dec7fdf2cc2f693c23d60b518aa415d08af1bd547"

  strings:
    $s1 = "(Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}