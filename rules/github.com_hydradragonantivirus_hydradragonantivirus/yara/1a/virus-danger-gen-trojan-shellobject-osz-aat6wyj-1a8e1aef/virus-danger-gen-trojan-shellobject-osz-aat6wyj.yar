rule Virus_Danger_Gen_Trojan_ShellObject_oSZ_aaT6Wyj {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.oSZ@aaT6Wyj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a1e019d2e2a681e46cdf65f2b96446252ceb960767f12497dbd761edeb2422f"

  strings:
    $s1 = "]whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}