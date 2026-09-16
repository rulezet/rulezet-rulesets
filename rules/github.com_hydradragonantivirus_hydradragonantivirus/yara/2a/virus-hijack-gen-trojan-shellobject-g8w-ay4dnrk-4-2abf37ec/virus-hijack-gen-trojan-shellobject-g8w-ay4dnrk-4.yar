rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b5b4399d437df354c12379b95c607b65c5be0eb0547917d402c35bdf044e9a6"

  strings:
    $s1 = "CAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}