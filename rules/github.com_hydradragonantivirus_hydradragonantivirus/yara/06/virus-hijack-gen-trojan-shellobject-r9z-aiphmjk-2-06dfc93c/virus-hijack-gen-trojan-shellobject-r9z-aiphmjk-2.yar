rule Virus_Hijack_Gen_Trojan_ShellObject_r9Z_aipHmJk_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r9Z@aipHmJk_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f17fc2828a89e078a3bba40d48c69fb64169b0872e1103d2f81d2c038966bb30"

  strings:
    $s1 = "leuD.]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}