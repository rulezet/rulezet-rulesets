rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_417_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_417_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "364c9a49926bb7e14755d7bd035e8b53759d05c2db3122487aef817c0aaa626a"

  strings:
    $s1 = "lr`sEEN" fullword ascii
    $s2 = "7`cODa" fullword ascii
    $s3 = "mAhA*g" fullword ascii
    $s4 = "}}TiDe" fullword ascii
    $s5 = "WEEN]?" fullword ascii
    $s6 = "STEY$&" fullword ascii
    $s7 = "IfFy>I" fullword ascii
    $s8 = "SKOO z" fullword ascii
    $s9 = "^[blAS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}