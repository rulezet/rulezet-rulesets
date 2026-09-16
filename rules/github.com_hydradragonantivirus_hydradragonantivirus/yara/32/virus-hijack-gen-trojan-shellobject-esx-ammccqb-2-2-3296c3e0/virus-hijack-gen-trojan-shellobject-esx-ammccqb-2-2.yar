rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f42e83a384959122bacab33f8f7245ff06d02ddf1204c7f277e5e892724aae8"

  strings:
    $s1 = "WoSign Time Stamping Signer0" fullword ascii
    $s2 = "Broad Knowledge Media Limited1&0$" fullword ascii
    $s3 = "Broad Knowledge Media Limited0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}