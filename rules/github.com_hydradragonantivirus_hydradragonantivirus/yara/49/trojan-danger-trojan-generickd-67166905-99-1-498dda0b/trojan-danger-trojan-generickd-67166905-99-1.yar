rule Trojan_Danger_Trojan_GenericKD_67166905_99_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_99_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d164bbd9484cf277bc626d66b9830fafc765c19551cabdf3f2d7d3a1a1715ed4"

  strings:
    $s1 = "]What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}