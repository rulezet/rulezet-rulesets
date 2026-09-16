rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9730cf77270c5933dceee69061e7afa3e35ad4a8cb8b041ce93e6aad7e74358"

  strings:
    $s1 = "C:\\DOCUME~1\\SUPERV~1\\LOCALS~1\\Temp\\Temporary Directory 1 for Invoice_OCT-02-2013.zip\\Invoice_OCT-02-2013.exe" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}