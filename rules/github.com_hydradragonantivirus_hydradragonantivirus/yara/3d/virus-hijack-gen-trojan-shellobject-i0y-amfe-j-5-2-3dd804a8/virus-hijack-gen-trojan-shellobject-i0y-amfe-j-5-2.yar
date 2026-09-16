rule Virus_Hijack_Gen_Trojan_ShellObject_i0Y_amFE__j_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Y@amFE@@j_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb9dbccb864cf84f73f31d0c5428a6f4791d8958fd34cb9c02da300bda618d6"

  strings:
    $s1 = "!;StUT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}