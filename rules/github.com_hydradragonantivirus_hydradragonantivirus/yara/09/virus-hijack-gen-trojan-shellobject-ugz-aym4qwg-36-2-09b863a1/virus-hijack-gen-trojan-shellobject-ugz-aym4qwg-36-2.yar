rule Virus_Hijack_Gen_Trojan_ShellObject_uGZ_ayM4QWg_36_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_36_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "610b29270ada8aa8d30979d4928bd451beca319cbefa13b3444b5a206314ffd2"

  strings:
    $s1  = "Execute GetCurrentContext err" fullword wide
    $s2  = "Execute m_jsBridge is nullptr" fullword wide
    $s3  = "frame!!!" fullword wide
    $s4  = ")Shanghai 2345 Mobile Technology Co., Ltd.1200" fullword ascii
    $s5  = ")Shanghai 2345 Mobile Technology Co., Ltd.0" fullword ascii
    $s6  = "name:%s,function_name:%s" fullword wide
    $s7  = "Get v8 context exception." fullword ascii
    $s8  = "Failed to register function." fullword ascii
    $s9  = "[%s] >> [L%d] [%s] %s << [%s(PID:%d)|(SID:%d)|%s(Line:%d)]" fullword wide
    $s10 = "[%s] >> [L%d] [%s] %s << [%s(PID:%d)|%s(SID:%d)|%s(Line:%d)]" fullword wide
    $s11 = "Failed to call function %s." fullword wide
    $s12 = "z#cess?s'" fullword ascii
    $s13 = "Sr#EXPLORE." fullword ascii
    $s14 = "unknown Exception" fullword wide
    $s15 = "DOS mode." fullword ascii
    $s16 = "This program canno" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}