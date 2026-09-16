rule Trojan_Hooker_Win32_Floxif_A_20 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a8f4c85546d11824ea5509f66a354ab1a5084a3a7e21d821606f40eb60eb823"

  strings:
    $s1  = " /q:a /c:\"install /q\"" fullword ascii
    $s2  = "/Error extracting '%s' to the temporary location'Error reading setup initialization file" fullword wide
    $s3  = "Kodak DIGITAL GEM Professional Plug-In 2.0.0.msi" fullword ascii
    $s4  = "'Error writing to the temporary location" fullword wide
    $s5  = "This Setup was created with a BETA VERSION of InstallShield DevStudio" fullword ascii
    $s6  = "CoCreateInstance failed with error 0x%lx, try a second approach." fullword ascii
    $s7  = "This Setup was created with an EVALUATION VERSION of InstallShield DevStudio" fullword ascii
    $s8  = "J#Version" fullword ascii
    $s9  = "J#Optional" fullword ascii
    $s10 = "Forcing item moniker %s into ROT..." fullword ascii
    $s11 = "Copyright (C) 2004 InstallShield Software Corp.          " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}