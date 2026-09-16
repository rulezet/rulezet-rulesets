rule Virus_Hijack_Gen_Trojan_ShellObject_g0W_aCiCCue {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g0W@aCiCCue.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c74f34116f4f1063f328c20726cc1fdbb60c449a4322176a8f33d2032784fe0"

  strings:
    $s1 = "The following software features use Internet protocols, which send to Microsoft (or" fullword ascii
    $s2 = "ACCEPT A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}