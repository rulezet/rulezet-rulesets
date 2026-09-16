rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aWD2a0g_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aWD2a0g_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9814c0f1e23fa6a4fdde2fcb702bd7fb3bac0e4dac2f5c2875ca6707a009eeae"

  strings:
    $s1 = "AAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}