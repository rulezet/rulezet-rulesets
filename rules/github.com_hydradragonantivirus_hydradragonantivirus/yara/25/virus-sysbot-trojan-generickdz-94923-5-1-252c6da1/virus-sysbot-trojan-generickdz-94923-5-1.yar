rule Virus_Sysbot_Trojan_GenericKDZ_94923_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKDZ.94923_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6dd5a2bbbaec7c7cc5d6c68070ceacacd7d364806bbe31dd365cf161a61d3c0"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "Refresh Processes" fullword ascii
    $s3 = "Proc Key Hook" fullword wide
    $s4 = "Title has" fullword ascii
    $s5 = "Length <" fullword ascii
    $s6 = "Exclude Proc(; split)" fullword ascii
    $s7 = "Exclude Title(; split)" fullword ascii
    $s8 = "filter%" fullword wide
    $s9 = "filter'" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}