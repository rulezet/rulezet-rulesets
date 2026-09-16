rule Trojan_Danger_Trojan_GenericKD_67166905_184_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_184_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcc56d0e0e62b686191986faee091ec64c61c7663ba4265a6d3ed1ff2dfe2308"

  strings:
    $s1 = "user minimum table in the licensing rules section" fullword ascii
    $s2 = " shall be counted." fullword ascii
    $s3 = "\"v%]*){sNEb" fullword ascii
    $s4 = "sUET!6r;/+s+E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}