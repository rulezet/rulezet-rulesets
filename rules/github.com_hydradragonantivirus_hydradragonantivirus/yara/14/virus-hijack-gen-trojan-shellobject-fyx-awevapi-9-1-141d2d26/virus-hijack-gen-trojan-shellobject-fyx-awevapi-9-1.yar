rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4367a1b8f5221f7e56ab7f14af8f6a7e54e8e0371d3eb6a52b7b7fb5c08eaa26"

  strings:
    $s1 = "m File" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}