rule Trojan_Autorun_Trojan_GenericKDZ_94847_327_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_327_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "539ead541319482752a0300093855f371871ec667549c7e324f5574280a42ab1"

  strings:
    $s1 = "breaching party continues reasonable efforts to cure the breach. You agree that if you " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}