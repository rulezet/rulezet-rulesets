rule Trojan_Danger_Trojan_GenericKD_67166905_205_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_205_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2ba0cada1b1b2092f3d098fb80d6f003ea11cd7c030fe8d5732adedc54402e3"

  strings:
    $s1 = "zSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}