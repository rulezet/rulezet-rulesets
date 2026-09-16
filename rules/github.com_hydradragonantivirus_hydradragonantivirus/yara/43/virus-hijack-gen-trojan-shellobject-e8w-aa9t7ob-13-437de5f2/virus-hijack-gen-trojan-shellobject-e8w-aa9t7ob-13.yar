rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8409793480bfc8241259329208aa3ded081c65d8e9cba6212c17fb671ce8569f"

  strings:
    $s1 = "Copyright (c) SkinBox Technology All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}