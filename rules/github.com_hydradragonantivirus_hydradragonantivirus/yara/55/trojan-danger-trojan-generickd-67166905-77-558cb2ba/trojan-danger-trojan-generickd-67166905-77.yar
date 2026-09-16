rule Trojan_Danger_Trojan_GenericKD_67166905_77 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_77.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a95ebea0f4ad32bcba7b791ad204aabc8e227860d61168c6b87ac39dce1a496b"

  strings:
    $s1 = "TaTe]]]T" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}