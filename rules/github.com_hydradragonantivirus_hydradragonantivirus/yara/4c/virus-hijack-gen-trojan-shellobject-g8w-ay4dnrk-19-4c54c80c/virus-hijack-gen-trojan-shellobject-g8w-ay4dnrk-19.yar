rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a5317a3ecf6d8f2e89c79a043f1486abe13dc8cd13b4271203f1d8563c140fd"

  strings:
    $s1 = "3OAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}