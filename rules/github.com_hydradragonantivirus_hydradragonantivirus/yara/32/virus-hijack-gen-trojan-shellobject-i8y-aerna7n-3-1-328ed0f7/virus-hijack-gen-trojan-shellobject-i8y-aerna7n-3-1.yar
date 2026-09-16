rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aerna7n_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aerna7n_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bddbab3057a600ce49dda6461ecd2077dc9ed6017686ab7578dfde0574a2b8fd"

  strings:
    $s1 = "Adobe Download Manager" fullword ascii
    $s2 = "        'title': '<b>Paris Hilton</b> - Wikipedia, the free encyclopedia'," fullword wide
    $s3 = "        'titleNoFormatting': 'Paris Hilton - Wikipedia, the free encyclopedia'," fullword wide
    $s4 = "Adobe Inc" fullword ascii
    $s5 = "<Module>{0439c0d7-04c2-4f00-a34c-4cd69d682ac4}" fullword ascii
    $s6 = ".Copyright 2019 Adobe Inc. All rights reserved." fullword ascii
    $s7 = "  'responseDetails': null," fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}