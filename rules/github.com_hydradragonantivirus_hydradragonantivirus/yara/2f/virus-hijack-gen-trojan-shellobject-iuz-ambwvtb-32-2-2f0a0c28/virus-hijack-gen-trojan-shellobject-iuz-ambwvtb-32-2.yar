rule Virus_Hijack_Gen_Trojan_ShellObject_iuZ_amBwvTb_32_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_32_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "428e84553adba36401ad745603ed35ad9b0db02ad0cf10d6b302ebfcfbb32154"

  strings:
    $s1 = "oCFaxEventExtended::CFaxEventExtended Can not allocate FAX_EVENT_EX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}