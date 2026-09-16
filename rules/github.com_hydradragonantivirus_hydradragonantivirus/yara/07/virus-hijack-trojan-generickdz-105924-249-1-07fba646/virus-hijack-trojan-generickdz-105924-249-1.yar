rule Virus_Hijack_Trojan_GenericKDZ_105924_249_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_249_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a90d835a97dae0a592d71eee3fdc16a6a9f832421c0daf4c662022d03e97fd17"

  strings:
    $s1 = "/C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"" fullword wide
    $s2 = "Dim PPath As String = \"APPDATA\", NPath As String = \"STARTUP\" : Try : IO.File.Copy(PPath, NPath) : Catch : End Try" fullword wide
    $s3 = "\"Powered by SmartAssembly 6.6.0.144" fullword ascii
    $s4 = "RunNet" fullword ascii
    $s5 = "Function Main" fullword ascii
    $s6 = "Public Class A" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}