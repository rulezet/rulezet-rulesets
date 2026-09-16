rule sig_20160322_2a08d02e5a8ad942f7c6d97c92530706 {
  meta:
    description = "datamaliciousorder - file 20160322_2a08d02e5a8ad942f7c6d97c92530706.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7afcaff30f609247e498d3bcc3d6ff60dbec1fc800a75488b7c82f83c042a14"

  strings:
    $s1  = "return WScript.CreateObject(yhGJo);" fullword ascii
    $s2  = "var yi = true  , nQbm = Xrr[7] + Xrr[9] + Xrr[11];" fullword ascii
    $s3  = "return FipIXWQ[0] + FipIXWQ[2] + FipIXWQ[4] + \".F\" + FipIXWQ[7] + FipIXWQ[9] + FipIXWQ[12] + FipIXWQ[14];" fullword ascii
    $s4  = "var FipIXWQ = QZRjr(mUumRVTyjR+\" \"+\"System tW BOETh Obj LhYNDv ect sIUThqn vGzhW\", \" \");" fullword ascii
    $s5  = "var Xrr = (\"2.XMLHTTP GPgoNWj SMdqe XML ream St lgToHHld AD PmTXebc O czOU D\").split(\" \");" fullword ascii
    $s6  = "WiwP.open(NnpQZ,tyKsg,false);" fullword ascii
    $s7  = "if (ercJH == 855-655){return true;} else {return false;}" fullword ascii
    $s8  = "function ZyJEdbLah(CNYnUmKpHNW) {" fullword ascii
    $s9  = "function hQyT(ercJH) {" fullword ascii
    $s10 = "function orLl(gWyTy) {" fullword ascii
    $s11 = "return new ActiveXObject(WEyYpp);" fullword ascii
    $s12 = "function lWKh(QHDWj,XHfar) {" fullword ascii
    $s13 = "return bcVt[wHrGph[0]];" fullword ascii
    $s14 = "return fodDKr.position=853-853;" fullword ascii
    $s15 = "function LMwhWrN(bcVt) {" fullword ascii
    $s16 = "function VEbb(yhGJo) {" fullword ascii
    $s17 = "function RHKZR(fodDKr) {" fullword ascii
    $s18 = "function wHkv(DtVxI) {" fullword ascii
    $s19 = "function xNMjHwGI(rlNP) {" fullword ascii
    $s20 = "if(F>=J.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}