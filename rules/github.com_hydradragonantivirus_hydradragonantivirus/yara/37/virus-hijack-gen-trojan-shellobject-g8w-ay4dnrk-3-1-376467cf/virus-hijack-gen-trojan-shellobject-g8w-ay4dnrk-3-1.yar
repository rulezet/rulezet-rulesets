rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3aa64d56048381740e1a9d5eb83856d2aab6e9d5f8acb2540aa834649efd0a49"

  strings:
    $s1 = "Unpossible" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}