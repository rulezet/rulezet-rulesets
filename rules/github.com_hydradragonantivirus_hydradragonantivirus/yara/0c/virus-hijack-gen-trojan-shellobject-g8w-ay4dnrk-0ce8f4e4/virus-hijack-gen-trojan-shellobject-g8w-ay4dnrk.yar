rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56350eec3d7110972f8b51b5d2fa36b1cd173e9ffa7a1537c2f8a06aced4825f"

  strings:
    $s1 = "\\America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}