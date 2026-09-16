rule Virus_Infector_Win32_Madangel_DIA {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Madangel.DIA.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef7d26b60309d10bb5441987c3cdda3e966b387df915715c8909739b2ed8c98f"

  strings:
    $s1 = "Angry Angel v3.0" fullword ascii
    $s2 = ".opened cache file: %S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}