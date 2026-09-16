rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a93fb36613adfd72bcf64e54acc155e3c84dff1004428a8d98cca8765839ad84"

  strings:
    $s1 = "kernel)V" fullword ascii
    $s2 = "ith delay %d6" fullword ascii
    $s3 = "leep)Creat+BAlloc`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}