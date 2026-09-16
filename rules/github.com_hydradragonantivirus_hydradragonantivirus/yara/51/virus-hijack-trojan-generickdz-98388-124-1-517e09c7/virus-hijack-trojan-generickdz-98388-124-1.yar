rule Virus_Hijack_Trojan_GenericKDZ_98388_124_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_124_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22314d502ff7b39b40c872f4b24d5c9273ddebc1c35b99f93f40d66bf45fa548"

  strings:
    $s1 = "ZD,fOnT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}