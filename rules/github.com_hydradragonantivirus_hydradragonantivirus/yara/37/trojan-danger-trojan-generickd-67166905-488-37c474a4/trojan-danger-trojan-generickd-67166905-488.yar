rule Trojan_Danger_Trojan_GenericKD_67166905_488 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_488.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0320f34c262f5b995455dd4d931fd9a5b4a2217802db8be765d070807685bea0"

  strings:
    $s1 = "Ruby 3.2.2 API Reference.lnk.tmp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}