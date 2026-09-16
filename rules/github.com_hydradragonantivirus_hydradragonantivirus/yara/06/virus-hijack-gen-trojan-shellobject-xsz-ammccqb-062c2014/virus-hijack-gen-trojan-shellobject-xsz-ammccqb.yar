rule Virus_Hijack_Gen_Trojan_ShellObject_xSZ_amMcCQb {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.xSZ@amMcCQb.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90d3a1c5d491703ae0dc46d3bf3ba3b11aa9ea09e95a10d8eed6643dc4c265f8"

  strings:
    $s1 = "`whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}