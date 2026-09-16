rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a232ba66b2b33f753bf55871255880796a5b0572889310f304c0275cf840d19c"

  strings:
    $s1 = "<Module>{98AEF126-6643-430F-A419-CF6E3887ADCE}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}