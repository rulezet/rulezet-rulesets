rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60403bd2b333596f196b519796b6926348867f98cc8a720a415a7b48d3c3412f"

  strings:
    $s1 = "]Dwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}