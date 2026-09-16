rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCkwazk_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCkwazk_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d04e052e8a292a758f217d311dee15b7882c57fed71f47758ea9459c4b4eaa47"

  strings:
    $s1 = "?{iRIs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}