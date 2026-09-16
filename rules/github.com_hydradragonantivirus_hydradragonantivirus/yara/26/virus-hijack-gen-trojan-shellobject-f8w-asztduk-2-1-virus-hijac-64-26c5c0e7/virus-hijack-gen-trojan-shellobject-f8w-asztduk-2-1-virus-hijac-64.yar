import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_2_1_Virus_Hijac_64 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87db8d9865cb602cafee3583c85a23cba4c6555f3ca9cfa049ab5d1929a952ea"
    hash2       = "55b20dde66c26821e457d319f2c38cdfc33690162f3ef1562a813ea129a7e083"

  strings:
    $s1  = "Error %u while loading TSU.DLL %ls" fullword ascii
    $s2  = "Error %u while extracting TSU.DLL to %ls" fullword ascii
    $s3  = "<description>Tarma InstallMate v7 Setup Loader</description>" fullword ascii
    $s4  = "Executable has no valid MZ signature" fullword ascii
    $s5  = "Executable has no .tsustub section" fullword ascii
    $s6  = "Inject$y" fullword ascii
    $s7  = "TSU Loader" fullword ascii
    $s8  = "Ws.ebonot be run in DOS mode." fullword ascii
    $s9  = "System#Qasnurces" fullword ascii
    $s10 = "Error %u while retrieving entry point from %ls" fullword ascii
    $s11 = "This installer is for Windows 2000 and later" fullword ascii
    $s12 = "Mum of missing yacht skipper numb" fullword ascii
    $s13 = ")leak:erZe77mm7c:Ee7meV77:I)e)`" fullword ascii
    $s14 = "Van Gaal appointed Man Utd boss" fullword ascii
    $s15 = "!This prog" fullword ascii
    $s16 = "Hide$UyzjfOameAttribute" fullword ascii
    $s17 = ";Zojr prog" fullword ascii
    $s18 = "o{i#hn DOS mode." fullword ascii
    $s19 = "<ewer]" fullword ascii
    $s20 = "heelRee/TMmw" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d48847f05c5fd88a678b7af8d736f338" and (8 of them)
    ) or (all of them)
}