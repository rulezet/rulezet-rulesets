rule Trojan_Danger_Trojan_GenericKD_67166905_455_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_455_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c354c0c2cdbf1f8d490759faaa74696b30c1fbfe6860e7e5e738b61e9e538e3f"

  strings:
    $s1 = "Zpolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}