rule _Trojan_Danger_Trojan_GenericKD_46147426_Virus_Hijack_Gen_Trojan_270 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.46147426.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_16.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51cf85f0909adb4c6b6473126e86916877768b1a1233cca35c189529e226cb43"
    hash2       = "d0a2b6770506c34ba0fa1eddc6de658234f1de956ff7edc7d8c857ad6ca4d387"
    hash3       = "ae504670119ccd3e69bfc73504f8c75d9a4d1571ab6e8e280b9dd6569708f617"
    hash4       = "481661ee588977620bbae38616277f88fbe6796ccad47d65205a8d061ef43bb1"
    hash5       = "d9431bfa0b15c0664e6da4d8c617ce5d2b9dc9af0016c8be47246bcb74418c95"
    hash6       = "c35804a74edf23b99ba415d32b56dcd2dec5a0332ea141327e02895dc66e5872"
    hash7       = "89a1af3a2afece7e197443049ab929855cd0cd7fe16b60c37a8af1f4d76aa1db"
    hash8       = "fd83aebb760b453007012f15679db7dbcb0e7807ba8c348834b8193e6d9cb17a"

  strings:
    $s1  = "Usage: Flattener.exe /Source:<Package Source> /Dest:<Package Destination> /ProductReleaseIds:<ProductReleaseId1>,<ProductRelease" wide
    $s2  = "<MachineChanges><FileSystem><File><Target><TargetFolder>%SFT_PKG_ROOT%\\..\\</TargetFolder><TargetName>Registry64.dat</TargetNam" wide
    $s3  = "Fixing ConfigXML: COM OutOfProcessEnabled=true" fullword wide
    $s4  = "Fixing ConfigXML: COM InProcessEnabled=true" fullword wide
    $s5  = "Flattener.exe: Version " fullword wide
    $s6  = " /IsLaunchedByFlattener:true /MergeMultiSzValues:true /Compression:Superfast /LogLevel:normal /LogType:replace" fullword wide
    $s7  = "&Microsoft Office Deployment Component." fullword ascii
    $s8  = "<assembly xsi:schemaLocation=\"urn:schemas-microsoft-com:asm.v1 assembly.adaptive.xsd\" manifestVersion=\"1.0\" xmlns:asmv1=\"ur" ascii
    $s9  = "<assembly xsi:schemaLocation=\"urn:schemas-microsoft-com:asm.v1 assembly.adaptive.xsd\" manifestVersion=\"1.0\" xmlns:asmv1=\"ur" ascii
    $s10 = "      <Target><TargetFolder>" fullword wide
    $s11 = "Fixing ConfigXML: " fullword wide
    $s12 = "Fixing ConfigXML: Objects Enabled=false" fullword wide
    $s13 = "Fixing ConfigXML: COM Mode=Integrated" fullword wide
    $s14 = "Fixing ConfigXML: SoftwareClients EmailEnabled=true" fullword wide
    $s15 = "Microsoft Office Deployment Component." fullword wide
    $s16 = "   /ProductReleaseIds:   Comma seperated list of Product Release Ids" fullword wide
    $s17 = "   /Cultures:            Comma seperate list of cultures" fullword wide
    $s18 = "Root\\VFS\\ProgramFilesX86\\Microsoft Office Debug\\" fullword wide
    $s19 = "Root\\VFS\\ProgramFilesX64\\Microsoft Office Debug\\" fullword wide
    $s20 = "ERROR: File is missing from the package: " fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}