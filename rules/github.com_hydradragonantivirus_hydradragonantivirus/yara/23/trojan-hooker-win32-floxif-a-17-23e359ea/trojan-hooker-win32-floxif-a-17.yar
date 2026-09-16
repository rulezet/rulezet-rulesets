rule Trojan_Hooker_Win32_Floxif_A_17 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ec24b9d46645f806dafdcc912e7f940c1db712cbe7a2e32a03e3bc08775de08"

  strings:
    $s1 = "AIRy'd>" fullword ascii
    $s2 = "$Free Folder BackU" fullword wide
    $s3 = "k#AQUA" fullword ascii
    $s4 = "fZ[dAwn" fullword ascii
    $s5 = "E>SUSU" fullword ascii
    $s6 = "YAnG#}" fullword ascii
    $s7 = "X?hOuR" fullword ascii
    $s8 = "d Software Corporation                          " fullword wide
    $s9 = " 1996-2000 InstallShield Software Corporation    " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}