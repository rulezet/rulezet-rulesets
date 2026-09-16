rule sig_20160313_46cf864fcee05ccbf831c7fce7351358 {
  meta:
    description = "datamaliciousorder - file 20160313_46cf864fcee05ccbf831c7fce7351358.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e707f22b21a11d223c213b5c1d4bed40dcc3a1696b7704ab381a598ed414861"

  strings:
    $s1  = "var Yy = true  , OBGN = CyF[7] + CyF[9] + CyF[11];" fullword ascii
    $s2  = "return ejRSYxM[0] + ejRSYxM[2] + ejRSYxM[4] + \".F\" + ejRSYxM[7] + ejRSYxM[9] + ejRSYxM[12] + ejRSYxM[14];" fullword ascii
    $s3  = "var CyF = (\"2.XMLHTTP jXPlRnc IgHkq XML ream St abtvyPRL AD xpVHVre O nBLq D\").split(\" \");" fullword ascii
    $s4  = "Fdjmt.open(tOJov,Lpaco,false);" fullword ascii
    $s5  = "var ejRSYxM = \"Sc OnPywnv r uERuMwrEO ipting pbQHKiv HZm ile UJXhodHQGsUfrx System tu CtXJE Obj npeBRn ect IIQcivK\".split(\" " ascii
    $s6  = "return yiTVk;" fullword ascii
    $s7  = "function ylBuCYee() {" fullword ascii
    $s8  = "if (AlTRP == 324-124){return true;} else {return false;}" fullword ascii
    $s9  = "return utxwHQz(yt,cgTIC[157-151]+cgTIC[837-830]+cgTIC[169-161]);" fullword ascii
    $s10 = "function kVUw(JsuxZ) {" fullword ascii
    $s11 = "return EZXrCdZ" fullword ascii
    $s12 = "function Vogh(Vbkng) {" fullword ascii
    $s13 = "return new ActiveXObject(vULBMa);" fullword ascii
    $s14 = "function XbaxL(xgMIWw) {" fullword ascii
    $s15 = "CPX = y; break; " fullword ascii
    $s16 = "return sMb.size;" fullword ascii
    $s17 = "function jQBNJryot(OaDZAXfifxp) {" fullword ascii
    $s18 = "function ulHg(syTth,aKbpN) {" fullword ascii
    $s19 = "function utxwHQz(ysXO,haGsd) {" fullword ascii
    $s20 = "function iGnmmhIt(sMb) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}