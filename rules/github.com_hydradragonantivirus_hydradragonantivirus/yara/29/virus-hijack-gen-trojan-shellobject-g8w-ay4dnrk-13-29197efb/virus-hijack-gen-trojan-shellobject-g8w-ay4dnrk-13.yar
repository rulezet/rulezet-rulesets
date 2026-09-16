rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9bd2da6af37f8ca53dd2ad732250ad5392cbe0358879e1adba2db988bf6b242"

  strings:
    $s1 = "NObs`>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}