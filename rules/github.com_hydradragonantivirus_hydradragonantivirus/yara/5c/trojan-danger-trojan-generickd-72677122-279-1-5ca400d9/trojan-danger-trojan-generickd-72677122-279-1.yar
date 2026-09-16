rule Trojan_Danger_Trojan_GenericKD_72677122_279_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_279_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31c783247faf4dafcf19bda7aac4bf7d6ff96c8e25a1216f187fb1f4eb1b6769"

  strings:
    $s1  = "?name@FFBaseLogger@FFBaseLog@@QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ" fullword ascii
    $s2  = "copy: %s, %s" fullword ascii
    $s3  = "fail to remove " fullword ascii
    $s4  = "Filmora Crash Reporter" fullword wide
    $s5  = "Copyright (c) 2020-2024 Wondershare. All rights reserved." fullword wide
    $s6  = "%S::%d code %d" fullword wide
    $s7  = "%S::%d count %d " fullword wide
    $s8  = "file %S::%d %d" fullword wide
    $s9  = "%S::%d file %s" fullword wide
    $s10 = "%S::%d return  %d" fullword wide
    $s11 = "catch SEHFilterFunction" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}