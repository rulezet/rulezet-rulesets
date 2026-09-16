rule Virus_Hijack_Win32_Grenam_Dam_G {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Grenam.Dam.G.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92efa9d5759496afcfe52af6c4ae40c7348a0692e360150c920068a6c22a2886"

  strings:
    $s1 = "Orientation,%B" fullword ascii
    $s2 = "Color@'B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}