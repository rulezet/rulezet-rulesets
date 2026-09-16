rule Trojan_Danger_Trojan_GenericKD_67166905_355 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_355.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "831bd65c0dcef7a0c3f108ffac26f79d22b39e5b8d7041e2066c2033a7a4c318"

  strings:
    $s1 = "Task Scheduler.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}