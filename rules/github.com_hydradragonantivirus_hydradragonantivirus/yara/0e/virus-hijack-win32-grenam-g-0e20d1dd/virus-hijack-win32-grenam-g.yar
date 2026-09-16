rule Virus_Hijack_Win32_Grenam_G {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Grenam.G.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b50b92ff9231c41a685462729f528cea99557ade3b69bd0b76e188cd22f76b2f"

  strings:
    $s1 = "Orientation,%B" fullword ascii
    $s2 = "Color@'B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}