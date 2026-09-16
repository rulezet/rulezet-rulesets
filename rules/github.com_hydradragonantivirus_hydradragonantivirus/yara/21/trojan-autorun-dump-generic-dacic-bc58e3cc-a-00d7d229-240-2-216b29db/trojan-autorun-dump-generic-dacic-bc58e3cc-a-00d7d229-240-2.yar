rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_240_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_240_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb11455a21bbf5fbe2b6c6f60c947813c049ec1e09a312a04ece300db3be4c9d"

  strings:
    $s1 = "ltNuJiWBcsh21uDh4R.wWYtKUGjExeOxPNkkB+ybWMBntoDgPWM8bwnD+Hm8G9e0irikfJadlIg`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
    $s2 = "EAn administrative password is required to exit." fullword ascii
    $s3 = "Possession" fullword ascii
    $s4 = "Quit Request" fullword ascii
    $s5 = "Please enter it belowV" fullword ascii
    $s6 = "<Module>{41E7EEF3-7A66-4D4F-ABB3-ED05CBADDCD0}" fullword ascii
    $s7 = " KaLA%" fullword ascii
    $s8 = "wEnT>e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}