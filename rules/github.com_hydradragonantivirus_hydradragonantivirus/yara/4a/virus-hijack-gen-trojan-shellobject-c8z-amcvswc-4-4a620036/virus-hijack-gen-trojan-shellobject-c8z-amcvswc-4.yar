rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_amCvSwc_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@amCvSwc_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5bb2573fdbeb599e5281c89ca4a7fd85beb0082355747a87a2b8bcd644a4b00"

  strings:
    $s1 = "|University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}