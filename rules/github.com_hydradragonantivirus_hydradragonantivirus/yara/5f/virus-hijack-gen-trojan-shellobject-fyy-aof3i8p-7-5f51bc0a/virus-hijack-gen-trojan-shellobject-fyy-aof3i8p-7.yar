rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_aOF3i8p_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36209e3115d01083f51c6950903d69e951a3018bbd0027f9796b37d47582dcc7"

  strings:
    $s1 = "CE`moup" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}