rule Trojan_Hooker_Trojan_Agent_AQNV {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Trojan.Agent.AQNV.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a1318635e6ae8df308813a1535b7a6506c0f88a386e310a5c69feba2d48c639"

  strings:
    $s1 = "\\Usb 2.0 Driver" fullword wide
    $s2 = "Usb 2.0 Driver" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}