rule Virus_Hijack_Gen_Trojan_ShellObject_CyZ_auPsdJb_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CyZ@auPsdJb_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0657505856f2aff0fb8db139e45dd92a6aec80d89c0347a6d8ea113dc41685b"

  strings:
    $s1 = "wAky@V0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}