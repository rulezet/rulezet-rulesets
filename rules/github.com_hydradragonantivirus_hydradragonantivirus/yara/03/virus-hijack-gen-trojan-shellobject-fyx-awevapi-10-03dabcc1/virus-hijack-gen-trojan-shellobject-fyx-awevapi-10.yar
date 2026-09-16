rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65dbe770a4804e6f8c607143210d8c973d918dc2a97b2a4207cb8343bace634a"

  strings:
    $s1 = "rOpP,Jg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}