rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34cc6c6b69091185e7cf657e098b967cfb832cea8a3c61b9e1db49fef8f98cf3"

  strings:
    $s1 = "@2America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}