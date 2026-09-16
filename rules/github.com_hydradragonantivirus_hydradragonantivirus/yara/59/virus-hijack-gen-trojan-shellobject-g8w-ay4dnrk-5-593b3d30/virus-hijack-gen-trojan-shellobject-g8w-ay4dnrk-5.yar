rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f34d375e57cee0e89b6f3e37c5fa88171f5f77920c8bf8ff6940666444ee35f1"

  strings:
    $s1 = "rAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}