rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abf9a8ee317c15b61cf0cfbc47fbc95afe9197e695f2953c730a781e6d2e85f3"

  strings:
    $s1 = "program and/or materials resulting from services (or direct product thereof) will be exported,`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}