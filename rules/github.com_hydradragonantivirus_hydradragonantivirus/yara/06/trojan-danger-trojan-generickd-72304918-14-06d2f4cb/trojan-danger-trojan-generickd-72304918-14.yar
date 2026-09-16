rule Trojan_Danger_Trojan_GenericKD_72304918_14 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b711b60aad4ef8f46435860cc99f120900dbbf9db6c6aaba6ac79d51844d5ab"

  strings:
    $s1 = "Task Scheduler.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}