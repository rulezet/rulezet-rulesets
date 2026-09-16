rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3207056247583d50cf63f82d758ef2ecc75b3c38115bc1921fe2907435e13bc"

  strings:
    $s1 = "UWAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}