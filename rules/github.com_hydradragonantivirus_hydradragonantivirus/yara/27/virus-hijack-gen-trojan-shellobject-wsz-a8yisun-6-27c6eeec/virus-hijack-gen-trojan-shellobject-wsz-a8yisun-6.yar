rule Virus_Hijack_Gen_Trojan_ShellObject_wSZ_a8YIsUn_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a8YIsUn_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d48b6ac4905756076ef77f34b79042871650a9eafff1ae9a07fb40f78e280226"

  strings:
    $s1 = "dremainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}