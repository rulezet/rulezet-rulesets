rule Trojan_Danger_Trojan_GenericKD_67166905_146 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_146.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a74ff587f7f7cdccd21a35bd0955a278fd924e95e541225e1a80e843a6e0ca33"

  strings:
    $s1 = "V[TRap?<RRRRRRRRRRna" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}