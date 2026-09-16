rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b828eea6522f0e10f081c3c33d6819f7f05cefb4aa5dc26e7a1aa33f142faade"

  strings:
    $s1 = "u}Outlook " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}