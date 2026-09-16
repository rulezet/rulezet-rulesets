rule Trojan_Danger_Trojan_GenericKD_72853156_294 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_294.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "254e8b55a4a8943bcc104b868218e67797c40d76a2dfdf7604a5727cd51102ed"

  strings:
    $s1 = "Task Manager.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}