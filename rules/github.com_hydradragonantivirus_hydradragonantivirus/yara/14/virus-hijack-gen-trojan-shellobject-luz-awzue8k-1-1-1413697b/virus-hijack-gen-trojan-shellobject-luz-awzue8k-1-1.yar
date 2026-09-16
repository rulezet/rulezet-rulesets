rule Virus_Hijack_Gen_Trojan_ShellObject_luZ_aWZUE8k_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.luZ@aWZUE8k_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5344bc6b5a1cef85ccee2e4b1b413e64d596fbed1a0d6b2f39e4eb83d13bc7"

  strings:
    $s1  = "\\srgb color space profile.icm" fullword wide
    $s2  = "no support for WCS profiles" fullword ascii
    $s3  = "Unable to read color profile" fullword ascii
    $s4  = "Can't retrieve color profile header" fullword ascii
    $s5  = "Unable to retrieve size of color profile" fullword ascii
    $s6  = "matching profile: %s" fullword ascii
    $s7  = "Invalid profile type %u" fullword ascii
    $s8  = "Unable to open color profile %u" fullword ascii
    $s9  = "profile file: %s" fullword ascii
    $s10 = "Can't open color profile" fullword ascii
    $s11 = "Can't retrieve color directory" fullword ascii
    $s12 = "can't retrieve color directory" fullword ascii
    $s13 = "Unable to allocate memory for color profile" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}