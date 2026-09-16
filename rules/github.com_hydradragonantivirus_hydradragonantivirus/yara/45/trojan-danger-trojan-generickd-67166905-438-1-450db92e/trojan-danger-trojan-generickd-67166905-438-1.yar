rule Trojan_Danger_Trojan_GenericKD_67166905_438_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_438_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb3dd57b690077896a29f30778b279a65a44476987f18a43bdc98f55402ce860"

  strings:
    $s1 = "}(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "}(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}