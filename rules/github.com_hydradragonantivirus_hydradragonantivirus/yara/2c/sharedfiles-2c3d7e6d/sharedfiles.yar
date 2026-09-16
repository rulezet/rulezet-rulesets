import "pe"
rule SharedFiles {
  meta:
    description = "8099 - file SharedFiles.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
    date        = "2021-12-12"
    hash1       = "c17e71c7ae15fdb02a4e22df4f50fb44215211755effd6e3fc56e7f3e586b299"

  strings:
    $s1  = "ButtonSkin.dll" fullword wide
    $s2  = "MyLinks.dll" fullword wide
    $s3  = "DragListCtrl.dll" fullword ascii
    $s4  = "whoami.exe" fullword ascii
    $s5  = "constructor or from DllMain." fullword ascii
    $s6  = "DINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
    $s7  = "kLV -{T" fullword ascii
    $s8  = "CtrlList1" fullword wide
    $s9  = "CtrlList2" fullword wide
    $s10 = "CtrlList3" fullword wide
    $s11 = "wox)YytbACl_<me*y3X(*lNCvY@8jsbePLfVHH!X2p2TdHa6+1hoo^1N7gNtwhki)Lbaso@*ne7" fullword ascii
    $s12 = "QX[gbL" fullword ascii  
    $s13 = "BasicScore" fullword ascii
    $s14 = ".?AVCDemoDlg@@" fullword ascii
    $s15 = "jLDfSektRC2FrOiWNzhbH3AsmBEIwg1U" fullword ascii
    $s16 = "9t$xt5" fullword ascii  
    $s17 = "DeAj1=n" fullword ascii
    $s18 = "WmaK|IG" fullword ascii
    $s19 = "oTRHz`R" fullword ascii
    $s20 = "VWATAUAVAWLc" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and
    (pe.imphash() == "c270086ea8ef591ab09b6ccf85dc6072" and pe.exports("BasicScore") or 8 of them)
}