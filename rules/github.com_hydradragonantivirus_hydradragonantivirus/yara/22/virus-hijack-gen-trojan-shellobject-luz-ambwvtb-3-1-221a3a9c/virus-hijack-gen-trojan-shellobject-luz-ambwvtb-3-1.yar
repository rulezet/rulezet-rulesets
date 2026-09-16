rule Virus_Hijack_Gen_Trojan_ShellObject_luZ_amBwvTb_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.luZ@amBwvTb_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aead3b29e4eb3a2c5499b67eb81a609bd85944a1d7ec6b9557be527a0c566929"

  strings:
    $s1  = "Opera Web" fullword wide
    $s2  = "Centrum" fullword ascii
    $s3  = "aube[a," fullword ascii
    $s4  = " Certified By ESET Smart Security" fullword ascii
    $s5  = "Illegal endpoint" fullword wide
    $s6  = "Number of vertices in a Graph must be nonnegative" fullword wide
    $s7  = "SharpGL Form" fullword wide
    $s8  = "Certified By ESET Smart Security" fullword wide
    $s9  = "arc tang" fullword wide
    $s10 = "gORb)9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}