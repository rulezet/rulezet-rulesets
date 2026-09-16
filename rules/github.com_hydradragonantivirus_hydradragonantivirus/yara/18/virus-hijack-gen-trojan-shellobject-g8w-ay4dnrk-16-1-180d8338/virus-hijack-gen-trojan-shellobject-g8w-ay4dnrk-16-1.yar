rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6396f1b9deaf5e2eb15d811dd316c52753bf90477b19bd73b618ab34952406cc"

  strings:
    $s1 = "Proker" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}