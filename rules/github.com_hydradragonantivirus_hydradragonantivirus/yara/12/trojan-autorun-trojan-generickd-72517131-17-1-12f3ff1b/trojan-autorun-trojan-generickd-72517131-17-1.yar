rule Trojan_Autorun_Trojan_GenericKD_72517131_17_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64a349dc56862faf26e51760a681d5a6741ec1db0e6e8242071abcb339c9f781"

  strings:
    $s1 = "|by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}