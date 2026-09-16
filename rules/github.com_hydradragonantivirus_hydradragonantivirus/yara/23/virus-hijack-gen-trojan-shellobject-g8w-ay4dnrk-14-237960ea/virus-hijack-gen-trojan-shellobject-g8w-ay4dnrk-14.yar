rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "035bd23ea0a0c671a95f0b6a476793559ea449fd130d3d3e63762595d37fc1ae"

  strings:
    $s1 = "#$[ChiN<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}