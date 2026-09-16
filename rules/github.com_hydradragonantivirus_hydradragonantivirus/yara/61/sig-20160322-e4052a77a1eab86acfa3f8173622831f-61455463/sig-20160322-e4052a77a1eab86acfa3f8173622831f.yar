rule sig_20160322_e4052a77a1eab86acfa3f8173622831f {
  meta:
    description = "datamaliciousorder - file 20160322_e4052a77a1eab86acfa3f8173622831f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85c622b16db64086b91f82e6d102babd0c40c8f5956f0b03a7c6387c1d1f5e66"

  strings:
    $s1  = "return WScript.CreateObject(knadd);" fullword ascii
    $s2  = "function RIrcFNxSj(aayIP) {" fullword ascii
    $s3  = "return lLIckRi[0] + lLIckRi[2] + lLIckRi[4] + \".F\" + lLIckRi[7] + lLIckRi[9] + lLIckRi[12] + lLIckRi[14];" fullword ascii
    $s4  = "var uW = true  , XYfy = EAQ[7] + EAQ[9] + EAQ[11];" fullword ascii
    $s5  = "var EAQ = (\"2.XMLHTTP CpoxJYR tahaM XML ream St ErmBcVzq AD AitiXrZ O Zvtc D\").split(\" \");" fullword ascii
    $s6  = "var lLIckRi = oHTQK(mhHjJySkWn+\" \"+\"System pD wNOYr Obj yyNnxY ect bEypleO SwoRK\", \" \");" fullword ascii
    $s7  = "if(s>=V.length) {break;}" fullword ascii
    $s8  = "return aJiw[yBecYj[0]];" fullword ascii
    $s9  = "return dHT.size;" fullword ascii
    $s10 = "return WQEOnzU(hv,FyMNI[969-963]+FyMNI[837-830]+FyMNI[186-178]);" fullword ascii
    $s11 = "return BaVj.ExpandEnvironmentStrings(WNiDp);" fullword ascii
    $s12 = "function LcDyYCQU(liVs) {" fullword ascii
    $s13 = "if (kCVkT == 1076-876){return true;} else {return false;}" fullword ascii
    $s14 = "if (ojnRS > 164836-531){return true;} else {return false;}" fullword ascii
    $s15 = "function wuCI(fevIP) {" fullword ascii
    $s16 = "function zhQw(TVEMA) {" fullword ascii
    $s17 = "oOO = s; break; " fullword ascii
    $s18 = "function UmLD(knadd) {" fullword ascii
    $s19 = "function vRUT(ojnRS) {" fullword ascii
    $s20 = "return aYwBy;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}