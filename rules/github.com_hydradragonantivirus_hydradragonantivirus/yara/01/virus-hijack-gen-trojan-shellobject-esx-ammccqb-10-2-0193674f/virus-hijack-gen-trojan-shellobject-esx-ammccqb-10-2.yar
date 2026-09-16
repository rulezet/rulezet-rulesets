rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30df064eedbe2d298b16c940b5736cd430c0208b62302b70211db1dfb6601c36"

  strings:
    $s1 = "WoSign Time Stamping Signer0" fullword ascii
    $s2 = "Broad Knowledge Media Limited1&0$" fullword ascii
    $s3 = "Broad Knowledge Media Limited0" fullword ascii
    $s4 = "Rich?!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}