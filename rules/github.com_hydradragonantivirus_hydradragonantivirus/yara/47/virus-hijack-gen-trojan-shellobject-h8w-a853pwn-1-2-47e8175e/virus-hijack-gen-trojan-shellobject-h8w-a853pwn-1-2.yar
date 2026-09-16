rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_a853Pwn_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@a853Pwn_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "512b124a8fe0fed67185d3099f1278a6403c99798c2011dd9f0cd2b1e6a96855"

  strings:
    $s1  = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRAMME\\GEMEINSAME DATEIEN\\MICROSOFT SHARED\\VBA\\VBA6\\VBE6.DLL#Visual" wide
    $s2  = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.2#0#C:\\Programme\\Gemeinsame Dateien\\Microsoft Shared\\Office10\\MSO.DLL#Microsof" wide
    $s3  = "DropFile.WriteLine \"WritePasswordTemplate:=\"\"\"\", Format:=wdOpenFormatAuto\"" fullword ascii
    $s4  = "DropFile.WriteLine \"PasswordTemplate:=\"\"\"\", Revert:=False, WritePasswordDocument:=\"\"\"\", _\"" fullword ascii
    $s5  = "DropFile.WriteLine \"Open Environ(\"\"WINDIR\"\") & \"\"\\alicia.exe\"\" For Binary Access Read As #1\"" fullword ascii
    $s6  = "DropFile.WriteLine \"Open \"\"C:\\alicia.doc\"\" For Binary Access Write As #1\"" fullword ascii
    $s7  = "DropFile.WriteLine \"If (Tasks.Item(I).Name = \"\"AVP.EXE\"\") Then Tasks.Item(I).Close\"" fullword ascii
    $s8  = "DropFile.WriteLine \"If (Tasks.Item(I).Name = \"\"IAMSERV.EXE\"\") Then Tasks.Item(I).Close\"" fullword ascii
    $s9  = "DropFile.WriteLine \"If (Tasks.Item(I).Name = \"\"AVPCC.EXE\"\") Then Tasks.Item(I).Close\"" fullword ascii
    $s10 = "DropFile.WriteLine \"If (Tasks.Item(I).Name = \"\"AMON.EXE\"\") Then Tasks.Item(I).Close\"" fullword ascii
    $s11 = "DropFile.WriteLine \"If (Tasks.Item(I).Name = \"\"FRW.EXE\"\") Then Tasks.Item(I).Close\"" fullword ascii
    $s12 = "DropFile.WriteLine \"If (Tasks.Item(I).Name = \"\"ESAFE.EXE\"\") Then Tasks.Item(I).Close\"" fullword ascii
    $s13 = "DropFile.WriteLine \"If (Tasks.Item(I).Name = \"\"AVPM.EXE\"\") Then Tasks.Item(I).Close\"" fullword ascii
    $s14 = "DropFile.WriteLine \"kill \"\"c:\\sys1.dr0\"\"\"" fullword ascii
    $s15 = "Set babe = fso.OpenTextFile(WScript.ScriptFullName, 1)" fullword ascii
    $s16 = "DropFile.WriteLine \"If (Tasks.Item(I).Name = \"\"SWEEP95\"\") Then Tasks.Item(I).Close\"" fullword ascii
    $s17 = "*\\G{00020905-0000-0000-C000-000000000046}#8.2#0#C:\\Programme\\Microsoft Office\\Office10\\MSWORD.OLB#Microsoft Word 10.0 Objec" wide
    $s18 = "DropFile.WriteLine \"If (Tasks.Item(I).Name = \"\"NAVRUNR\"\") Then Tasks.Item(I).Close\"" fullword ascii
    $s19 = "Set DropFile = FSO.CreateTextFile(\"c:\\sys1.dr0\", True)" fullword ascii
    $s20 = "DropFile.WriteLine \"If (Tasks.Item(I).Name = \"\"VSECOMR\"\") Then Tasks.Item(I).Close\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}