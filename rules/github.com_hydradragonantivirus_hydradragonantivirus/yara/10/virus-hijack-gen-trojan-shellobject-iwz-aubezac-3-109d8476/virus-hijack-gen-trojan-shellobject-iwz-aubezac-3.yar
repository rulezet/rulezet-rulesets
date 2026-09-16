rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63417d3b3335130c717fc2725842852b734a32e4fb38039a3e01ffe8ff6d26d6"

  strings:
    $s1 = "Avautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}