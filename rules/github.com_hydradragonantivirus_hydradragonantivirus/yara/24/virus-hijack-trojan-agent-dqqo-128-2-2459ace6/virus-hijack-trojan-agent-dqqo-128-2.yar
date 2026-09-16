rule Virus_Hijack_Trojan_Agent_DQQO_128_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_128_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da5c2d142c1f91478d40490c42c1d58c87a26a865de1a097449b5ee776c41204"

  strings:
    $s1  = "[%s]%s GetModuleHandle GameSafe.dll Error!" fullword wide
    $s2  = "[%s]%s Generate dr.dll Path Error!" fullword wide
    $s3  = "[%s]progress = %d  result = %d" fullword wide
    $s4  = "[%s]Begain Check" fullword wide
    $s5  = "[%s]%s  No Need SetUp" fullword wide
    $s6  = "[%s]%s  pArgsList is NULL" fullword wide
    $s7  = "paGE?I" fullword ascii
    $s8  = "[%s]End Check" fullword wide
    $s9  = " iShowUI = 0  No Need SHow" fullword wide
    $s10 = "Copyright (C) 1998-2017 Tencent. All Rights Reserved" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}