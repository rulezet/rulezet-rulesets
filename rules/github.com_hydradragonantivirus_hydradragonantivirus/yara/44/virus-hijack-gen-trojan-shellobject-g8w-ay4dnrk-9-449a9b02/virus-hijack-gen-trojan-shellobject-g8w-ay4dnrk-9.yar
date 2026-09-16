rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcc44c2fcc32c5454ab738c9cbd4e54a7c5c06f25b79aa723fffb752bb3b90af"

  strings:
    $s1 = "JUAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}