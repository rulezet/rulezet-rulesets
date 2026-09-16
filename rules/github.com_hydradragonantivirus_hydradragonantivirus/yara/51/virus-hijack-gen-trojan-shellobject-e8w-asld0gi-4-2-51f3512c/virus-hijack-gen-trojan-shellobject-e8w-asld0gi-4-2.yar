rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52efc4658cb11d9d9e83f166418a38e1e89626c367b74b1780d8cb3eebc7f4bb"

  strings:
    $s1 = "KERNEL$:>" fullword ascii
    $s2 = "ication error" fullword ascii
    $s3 = "uld not blot" fullword ascii
    $s4 = "e[uNau" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}