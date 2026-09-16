rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_24_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_24_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "596f6a469125ded393f2d6c1edca82fd2eab923f58613faf4fd66a5dadca8529"

  strings:
    $s1  = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (InfList_mp3.txt) do copy /y %0 \"%%j:%%k\"" fullword ascii
    $s2  = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (InfList_txt.txt) do copy /y %0 \"%%j:%%k\"" fullword ascii
    $s3  = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (InfList_lnk.txt) do copy /y %0 \"%%j:%%k\"" fullword ascii
    $s4  = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (InfList_mp4.txt) do copy /y %0 \"%%j:%%k\"" fullword ascii
    $s5  = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (InfList_.py.txt) do copy /y %0 \"%%j:%%k\"" fullword ascii
    $s6  = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (InfList_pdf.txt) do copy /y %0 \"%%j:%%k\"" fullword ascii
    $s7  = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (InfList_xml.txt) do copy /y %0 \"%%j:%%k\"" fullword ascii
    $s8  = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (InfList_png.txt) do copy /y %0 \"%%j:%%k\"" fullword ascii
    $s9  = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (InfList_exe.txt) do copy /y %0 \"%%j:%%k\"" fullword ascii
    $s10 = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (InfList_doc.txt) do copy /y %0 \"%%j:%%k\"" fullword ascii
    $s11 = "echo Mail.to=ol.GetNameSpace(\"MAPI\").AddressLists(1).AddressEntries(x)>>%SystemDrive%\\mail.vbs" fullword ascii
    $s12 = "rem Disable Computer By Deleting hal.dll" fullword ascii
    $s13 = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (FIleList_mp4.txt) do del \"%%j:%%k\"" fullword ascii
    $s14 = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (FIleList_lnk.txt) do del \"%%j:%%k\"" fullword ascii
    $s15 = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (FIleList_xml.txt) do del \"%%j:%%k\"" fullword ascii
    $s16 = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (FIleList_doc.txt) do del \"%%j:%%k\"" fullword ascii
    $s17 = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (FIleList_exe.txt) do del \"%%j:%%k\"" fullword ascii
    $s18 = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (FIleList_png.txt) do del \"%%j:%%k\"" fullword ascii
    $s19 = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (FIleList_mp3.txt) do del \"%%j:%%k\"" fullword ascii
    $s20 = "echo Y | FOR /F \"tokens=1,* delims=: \" %%j in (FIleList_txt.txt) do del \"%%j:%%k\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}