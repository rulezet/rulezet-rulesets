rule Virus_Hijack_Generic_Dacic_2527_020ED395 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Generic.Dacic.2527.020ED395.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "605e7d016ec0e3ffcd81f4726d5a7dfeb3f418782553e2b98969466cb3c08122"

  strings:
    $s1 = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" fullword wide
    $s2 = "echo Y| cacls " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}