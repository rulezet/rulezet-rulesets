rule Virus_Hijack_Gen_Trojan_ShellObject_e4Y_a05ilOd_15_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4Y@a05ilOd_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1c901ab44bcbc4fb2248a8fd7a45934d74e46d61b7474b468182f3454ba35ac"

  strings:
    $x1 = "powershell -ExecutionPolicy Bypass -windowstyle hidden -noexit -Command [Reflection.Assembly]::Load([System.Convert]::Frombase64" ascii
    $x2 = "powershell -ExecutionPolicy Bypass -windowstyle hidden -noexit -Command [Reflection.Assembly]::Load([System.Convert]::Frombase64" ascii
    $s3 = "String((Get-ItemProperty HKCU:\\Software).microvps)).EntryPoint.Invoke($null,$null)::[Reflection.Assembly]" fullword ascii
    $s4 = "Hello i made this for my brother he is a new in .NEt so i made this to help him  Now i had submitted it on planet source code to" ascii
    $s5 = "Hello i made this for my brother he is a new in .NEt so i made this to help him  Now i had submitted it on planet source code to" ascii
    $s6 = "Registration%" fullword ascii
    $s7 = " help others . So if U like this then please vote for me I think u people like it" fullword ascii
    $s8 = " National 2007" fullword wide
    $s9 = "Registration$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}