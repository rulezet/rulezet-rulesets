rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b931d570b89396434ae94e4969993ac00d33137c49a7d35960e2d78ddc0a630e"

  strings:
    $s1 = "Gormed" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}