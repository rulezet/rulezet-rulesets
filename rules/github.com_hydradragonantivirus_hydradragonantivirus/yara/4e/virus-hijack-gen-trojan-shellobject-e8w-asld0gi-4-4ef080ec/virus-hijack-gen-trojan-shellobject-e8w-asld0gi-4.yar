rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe84d8acc790459fddc6936f5a16655c3c8a1c21e424a6b91467eacd36aece8e"

  strings:
    $s1 = "-&Outlook " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}