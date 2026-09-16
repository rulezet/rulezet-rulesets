rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_21 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3903f08f5da41f68d24bdd635f452b0be97937e7d9c793e56571af4a56a22133"

  strings:
    $s1 = "%uAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}