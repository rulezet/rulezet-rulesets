rule Virus_Hijack_Trojan_Agent_DQQO_140_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_140_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c6bd35f8ac1e873ba3bf730aff0b4d5a3f61bf6ed1eb1bcd011aefba872972"

  strings:
    $s1 = "\\Usb 2.0 Driver" fullword wide
    $s2 = "Usb 2.0 Driver" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}