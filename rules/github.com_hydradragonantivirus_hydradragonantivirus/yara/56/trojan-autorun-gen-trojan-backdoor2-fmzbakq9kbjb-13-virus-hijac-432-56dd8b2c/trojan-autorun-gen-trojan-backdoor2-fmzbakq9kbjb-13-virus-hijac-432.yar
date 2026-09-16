import "pe"
rule _Trojan_Autorun_Gen_Trojan_Backdoor2_fmZbaKq9kbjb_13_Virus_Hijac_432 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Trojan.Backdoor2.fmZbaKq9kbjb_13.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_165_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_169_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_170_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_208_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_218_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735754bfd40bd8a998d81b358da7677687845004060e7c7f795b60136275fbc5"
    hash2       = "78cc9f514548e01fdca40f552013d11af4669d3ce2e26bd4e91090c0660ae8e9"
    hash3       = "5ae9799a975e22eab9ea28cbc9103feb954d7241dcd7c2270b72cc18c9201236"
    hash4       = "37865158a996519922eef811beee21cc6c12e2a710eefda22d2e1c2f20c91150"
    hash5       = "db9657e33d0bbd1607667db444db64731d4e888cdefeaee410e72a2c41746a20"
    hash6       = "05e672f491a10f6b69de690fcc59d3f50050f8fdc7c0aa947523ab2de51bf9e5"

  strings:
    $s1  = "[K{PID:%u} setsid executed (pgid=%i)" fullword ascii
    $s2  = "[K{PID:%u} open(`/dev/ptmx`) failed (%i): %s" fullword ascii
    $s3  = "[K{PID:%u} open(`%s`) failed (%i): %s" fullword ascii
    $s4  = "[33;40m{PID:%u} ce_forkpty child: std=%i, err=%i" fullword ascii
    $s5  = "[33;40m{PID:%u} stderr is already %i" fullword ascii
    $s6  = "[31;40m{PID:%u} opening slave `%s`" fullword ascii
    $s7  = "[33;40m{PID:%u} stdout is already %i" fullword ascii
    $s8  = "[31;40m{PID:%u} slave handle is (%i)" fullword ascii
    $s9  = "[33;40m{PID:%u} stdin is already %i" fullword ascii
    $s10 = "[31;40m{PID:%u} %s handle is (%i)" fullword ascii
    $s11 = "stderr master" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "62a960f8ad30d2ced6e939ce901644b8" and (8 of them)
    ) or (all of them)
}