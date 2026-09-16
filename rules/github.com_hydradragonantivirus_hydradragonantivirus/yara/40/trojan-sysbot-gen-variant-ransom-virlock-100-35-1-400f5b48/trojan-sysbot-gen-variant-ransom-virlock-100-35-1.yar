rule Trojan_Sysbot_Gen_Variant_Ransom_VirLock_100_35_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94416f9124b9da268b6f977cdc60a3848209d75238d487a597a96805c0618604"

  strings:
    $s1 = "TZT\\\\eTppTfm]TaTe]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}