rule Trojan_Danger_Trojan_GenericKD_67166905_277_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_277_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dff8101e719e62f3d826e2684d1f479007cdc58dda9ab21d0e5bfe5425455022"

  strings:
    $s1 = ">+University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}