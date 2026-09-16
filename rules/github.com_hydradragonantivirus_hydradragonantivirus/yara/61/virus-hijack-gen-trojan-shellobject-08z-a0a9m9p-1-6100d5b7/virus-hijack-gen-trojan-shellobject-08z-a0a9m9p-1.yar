rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbe2348b8bafcbcba4a5008381785dbdc863978dcf2c5b0a8cddaf9c725d80ca"

  strings:
    $s1 = "#Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}