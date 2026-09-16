rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_auel1S_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@auel1S_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "293846c92512c483fba980045aeae3d68d45181f6fca6a529037b4179a5c1f9b"

  strings:
    $s1 = "8Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}