rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "355ad292a8280a28c2290ff6fbb9c04383b3345fe7adcbf6ebe40abd265636ed"

  strings:
    $s1 = "program and/or materials resulting from services (or direct product thereof) will be exported,`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}