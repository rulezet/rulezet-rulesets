rule sig_20160309_d4c850d601ec8536e78ac194fdef7130 {
  meta:
    description = "datamaliciousorder - file 20160309_d4c850d601ec8536e78ac194fdef7130.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0c0ab2b0c5910f8a19641041a049ae229f8a3603b6ad7bf40b76bdcd5532a9c"

  strings:
    $s1  = "var evX = (\"2.XMLHTTP YPDvDZJ qVafa XML ream St ppAjcXUw AD dLLDQZk O rvVc D\").split(\" \");" fullword ascii
    $s2  = "var VL = true  , DXiE = evX[7] + evX[9] + evX[11];" fullword ascii
    $s3  = "return XNRvlTb[0] + XNRvlTb[2] + XNRvlTb[4] + \".F\" + XNRvlTb[7] + XNRvlTb[9] + XNRvlTb[12] + XNRvlTb[14];" fullword ascii
    $s4  = "var XNRvlTb = \"Sc nQZjSyk r GXrAcmQxv ipting PKAcCVf FIl ile MTaupREEwSwkPU System TV lrsxA Obj qiueCc ect UbJLCGn\".split(\" " ascii
    $s5  = "function xrzk(ozTfF) {" fullword ascii
    $s6  = "function LbENsKEW() {" fullword ascii
    $s7  = "function elqNaPS(POfF) {" fullword ascii
    $s8  = "return new ActiveXObject(xSVoXF);" fullword ascii
    $s9  = "function iJpK(TtDuL) {" fullword ascii
    $s10 = "function BnoFXpKM(xIWZP,mAWBnI) {" fullword ascii
    $s11 = "function wnRt(ZWdvC) {" fullword ascii
    $s12 = "return POfF.responseBody;" fullword ascii
    $s13 = "return WZOvKcp" fullword ascii
    $s14 = "function ctfk(mksHA) {" fullword ascii
    $s15 = "if (TtDuL > 192688-367){return true;} else {return false;}" fullword ascii
    $s16 = "function ODTQ(yAzvu,DhmEP) {" fullword ascii
    $s17 = "function Hnco(KzcWn) {" fullword ascii
    $s18 = "function gqSRx(xSVoXF) {" fullword ascii
    $s19 = "return rRHBDOt(XJ,zPDfI[260-254]+zPDfI[158-151]+zPDfI[262-254]);" fullword ascii
    $s20 = "function rRHBDOt(Sodn,bmYcC) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}