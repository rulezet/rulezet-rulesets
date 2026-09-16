rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0644d863e6d562c1a87fd59283d3772f3c82cf1a397d73a960986b0bdfe75ea"

  strings:
    $s1 = "bmd.exe /c ping 127.0" fullword ascii
    $s2 = "%s \"%s\",Viewer %s" fullword ascii
    $s3 = "I,Viewer " fullword ascii
    $s4 = "upper%X-?lowz" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}