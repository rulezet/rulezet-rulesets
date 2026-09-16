rule _Trojan_Sysbot_Win32_Sality_3_Virus_Hijack_GenPack_Backdoor_Hang_484 {
  meta:
    description = "datamaliciousorder - from files Trojan.Sysbot_Win32.Sality.3.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_469_2.vir, Virus.Sysbot_Win32.Sality.3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9517d49a8422edd7a5306c6438423042f9fb8ebbac9f46af771244bd329c6b50"
    hash2       = "6e591e844645cb69cabdade3ddd5ffabe9fd78527dc0bdc82c7ec42ab0ab9ccb"
    hash3       = "3770b4f5b74c4e382078cef59f521642bbec4ce2590d89ca86ae0a88e3a05544"

  strings:
    $s1 = ".?AV?$RefCountedThreadSafe@VBindStateBase@internal@base@@U?$DefaultRefCountedThreadSafeTraits@VBindStateBase@internal@base@@@3@@" ascii
    $s2 = ".?AV?$RefCountedThreadSafe@VBindStateBase@internal@base@@U?$DefaultRefCountedThreadSafeTraits@VBindStateBase@internal@base@@@3@@" ascii
    $s3 = "Check failed: !bind_state_ || bind_state_->HasOneRef(). " fullword ascii
    $s4 = ".?AVRefCountedThreadSafeBase@subtle@base@@" fullword ascii
    $s5 = ".?AVBindStateBase@internal@base@@" fullword ascii
    $s6 = "base@@" fullword ascii
    $s7 = "tracing categories exhausted; must increase TRACE_EVENT_MAX_CATEGORIES" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}