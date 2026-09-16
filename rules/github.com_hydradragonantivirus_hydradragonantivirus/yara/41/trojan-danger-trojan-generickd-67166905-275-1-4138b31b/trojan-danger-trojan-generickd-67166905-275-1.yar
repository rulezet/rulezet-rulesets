rule Trojan_Danger_Trojan_GenericKD_67166905_275_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_275_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acfa773e5c237e67334e8b40f5a57c0543b19041001e4fbf9c1c206720020d43"

  strings:
    $s1 = "h'Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}