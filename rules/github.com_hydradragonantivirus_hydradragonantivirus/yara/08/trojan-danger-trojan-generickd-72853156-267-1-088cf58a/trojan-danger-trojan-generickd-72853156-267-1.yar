rule Trojan_Danger_Trojan_GenericKD_72853156_267_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_267_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd7cd4914ec36b105fc7818de993db2e8de2e3e16cabc05fb85c288af17e596d"

  strings:
    $s1 = "those features in any way that cSysqamqqvaqqdSysqemdlwytSysqemoglnmSysqemvoxutSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaq" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}