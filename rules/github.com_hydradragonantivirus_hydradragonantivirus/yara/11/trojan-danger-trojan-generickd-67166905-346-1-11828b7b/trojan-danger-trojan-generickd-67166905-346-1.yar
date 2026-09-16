rule Trojan_Danger_Trojan_GenericKD_67166905_346_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_346_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5161f5e348ab610de9a0d397d7307b533702f4766101cbf79a60cbfb15bc0d0a"

  strings:
    $s1 = "$G(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "$G(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s3 = "and software vendors, so that they can use the information to i`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}