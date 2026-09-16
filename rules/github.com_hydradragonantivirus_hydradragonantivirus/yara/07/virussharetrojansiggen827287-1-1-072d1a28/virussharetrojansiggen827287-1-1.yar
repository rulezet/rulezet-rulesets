rule VirusShareTrojanSiggen827287_1_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen827287_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8163ac1eade3c60116eb76ec9c127a6f33e361c89adecf0c7fb1b819ebcfacad"

  strings:
    $s1 = "F_controlfp_s(((void *)0), 0x00010000, 0x00030000)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}