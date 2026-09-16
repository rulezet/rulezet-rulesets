rule Trojan_Danger_Trojan_GenericKD_72304918_188_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_188_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe6c0b7b7929cc3ac9f80bedc4c9b87e5be0049ed746890582abc9161723e281"

  strings:
    $s1 = ">cvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}