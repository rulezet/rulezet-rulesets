rule Virus_Hijack_Gen_Trojan_ShellObject_oyZ_aeWgNZc_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oyZ@aeWgNZc_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4a2e95f11dca086bcd97058458d6b31d13105736c7be563a9f639653eab662b"

  strings:
    $s1 = "SELECT Name, VideoProcessor FROM Win32_VideoController" fullword wide
    $s2 = "Shell Infrastructure Host" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}