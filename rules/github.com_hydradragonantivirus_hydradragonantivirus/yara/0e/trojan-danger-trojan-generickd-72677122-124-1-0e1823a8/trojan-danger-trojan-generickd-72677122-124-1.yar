rule Trojan_Danger_Trojan_GenericKD_72677122_124_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_124_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfc49afa0e40aa85fb52ced21e958d527bcac626c34ae92615ae318a3f03981b"

  strings:
    $s1 = "Q}REpS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}