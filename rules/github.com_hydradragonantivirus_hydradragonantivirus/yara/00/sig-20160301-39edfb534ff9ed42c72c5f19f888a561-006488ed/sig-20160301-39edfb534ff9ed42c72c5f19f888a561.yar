rule sig_20160301_39edfb534ff9ed42c72c5f19f888a561 {
  meta:
    description = "datamaliciousorder - file 20160301_39edfb534ff9ed42c72c5f19f888a561.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea1f9ee2308c7107b5567bc005621cb8df384a43118c933c91f404affc27cf5c"

  strings:
    $s1  = "var LQ = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(MnEBC);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + AUcDxHF + \".F\" + EvadyKRbZn + eEXBv + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var sAb = (jsD + \"TTP\" + \" HTdgrva vjwgV XML ream St UvLotEwQ AD mMOiQhK OD\").split(\" \");" fullword ascii
    $s5  = "var oM = true  , QTcC = sAb[7] + \"\" + sAb[9];" fullword ascii
    $s6  = "bPRHg.open(BDrps,OHBlq,false);" fullword ascii
    $s7  = "function RjJY(bPRHg,OHBlq,BDrps) {" fullword ascii
    $s8  = "if (rfPQT == 861-661){return true;} else {return false;}" fullword ascii
    $s9  = "function fDWO(ydCUd) {" fullword ascii
    $s10 = "function ugOZgLxRk(fcgkubzITuK) {" fullword ascii
    $s11 = "function qGcv(ZHSqe) {" fullword ascii
    $s12 = "function CNal(AWhfR,rYFNm) {" fullword ascii
    $s13 = "function zNiq(ZnobW,OUjtV) {" fullword ascii
    $s14 = "return Dw.ExpandEnvironmentStrings(LQ);" fullword ascii
    $s15 = "function OeGO(TCvGZ) {" fullword ascii
    $s16 = "Xko = L; break; " fullword ascii
    $s17 = "if (((new Date())>0,7146435888)) {" fullword ascii
    $s18 = "function nneC(rfPQT) {" fullword ascii
    $s19 = "return ydCUd.status;" fullword ascii
    $s20 = "function wLMX(otytO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}