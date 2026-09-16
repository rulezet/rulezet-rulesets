rule sig_20160302_b7140e8ff88c40a06614b4351c5a37d5 {
  meta:
    description = "datamaliciousorder - file 20160302_b7140e8ff88c40a06614b4351c5a37d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5527637ad0811f87e130e1c3cb2383f45a22d41c20be6501915f412aaa722cff"

  strings:
    $s1  = "var SO = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(pfaKG);" fullword ascii
    $s3  = "var CTu = (BTT + \"TTP\" + \" QeySiWL WSoeL XML ream St twPKtvSV AD mqtxMvl OD\").split(\" \");" fullword ascii
    $s4  = "var sJ = true  , HbeU = CTu[7] + \"\" + CTu[9];" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + IEphPks + \".F\" + WBZyYIuXWc + bksmb + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "YPmwH.open(VjEdt,VvMDw,false);" fullword ascii
    $s7  = "if (aPwLA == 554-354){return true;} else {return false;}" fullword ascii
    $s8  = "if(L>=k.length) {break;}" fullword ascii
    $s9  = "function CiMIMUZAH(tAaGQAXMvCj) {" fullword ascii
    $s10 = "function Guqh(wZwrb) {" fullword ascii
    $s11 = "return rvMUa.status;" fullword ascii
    $s12 = "if (BYDDi > 190700-823){return true;} else {return false;}" fullword ascii
    $s13 = "function GuwinkWL() {" fullword ascii
    $s14 = "function aNDh(pfaKG) {" fullword ascii
    $s15 = "return CnLXF;" fullword ascii
    $s16 = "if (((new Date())>0,7879294888)) {" fullword ascii
    $s17 = "function zWog(YPmwH,VvMDw,VjEdt) {" fullword ascii
    $s18 = "function bnZR(wMCFI,heODN) {" fullword ascii
    $s19 = "return wQ.ExpandEnvironmentStrings(SO);" fullword ascii
    $s20 = "function SwKws(yzxzaW) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}