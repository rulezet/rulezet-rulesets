rule Trojan_Autorun_Trojan_GenericKDZ_94847_421_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_421_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a25707ca4cf2be0aac098369450f776a2b5bca2fde9c6576520570bf16636e50"

  strings:
    $s1 = "4(orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}