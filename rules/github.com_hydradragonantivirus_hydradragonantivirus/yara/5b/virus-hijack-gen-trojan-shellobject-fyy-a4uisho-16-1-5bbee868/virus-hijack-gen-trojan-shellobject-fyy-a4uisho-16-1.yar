rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b620f7e6fc656cd1d9bfb0825f7a41d365a0336111944657798d18cba2f0f62"

  strings:
    $s1  = "runtime error" fullword wide
    $s2  = "Nircular decoder table entry" fullword wide
    $s3  = "<description>Safel</description>" fullword ascii
    $s4  = "*Emage width too small for contained frames" fullword wide
    $s5  = "doesn't support streaming)Abject type not supported for Justefytion+Smage height too small for contained frames" fullword wide
    $s6  = "Envalid Image trailerAEnternal error: Extension Instance does not match Extension Label,Ansupported Application Extension block " wide
    $s7  = "count out of bounds" fullword wide
    $s8  = "list index out of bounds" fullword wide
    $s9  = "invalid windows image" fullword wide
    $s10 = "index data dictionary count" fullword wide
    $s11 = "Invalid stream Justefytion" fullword wide
    $s12 = "Anknown GIF block type" fullword wide
    $s13 = "You not assign w to t" fullword wide
    $s14 = "Educate" fullword ascii
    $s15 = "list capacity out of bounds" fullword wide
    $s16 = "Best Application" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}