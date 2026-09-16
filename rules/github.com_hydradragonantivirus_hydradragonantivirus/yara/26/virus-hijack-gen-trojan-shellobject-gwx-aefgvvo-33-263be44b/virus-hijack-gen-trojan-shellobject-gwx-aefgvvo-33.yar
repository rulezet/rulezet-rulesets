rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_33 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "642413d62953fae8fd5cbbec5c69f5a50f68eaa2e49cffd9f9148dbaa5eaec43"

  strings:
    $s1 = "`shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}