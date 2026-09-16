rule Trojan_Danger_Trojan_GenericKD_67166905_70_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_70_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68520b470a0118c308be080209001ae8b96af1a5df2b22cba4373d7f92afbefe"

  strings:
    $s1 = "features or not use them. For more informa tion about these features, see the Offi`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}