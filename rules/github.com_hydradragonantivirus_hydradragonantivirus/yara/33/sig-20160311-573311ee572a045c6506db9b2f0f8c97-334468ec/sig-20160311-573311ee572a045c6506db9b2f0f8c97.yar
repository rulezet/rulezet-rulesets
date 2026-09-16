rule sig_20160311_573311ee572a045c6506db9b2f0f8c97 {
  meta:
    description = "datamaliciousorder - file 20160311_573311ee572a045c6506db9b2f0f8c97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b6e79aa20c03190ed2cc0cf4a378097ce49ba0d735660a4db549619dfd4d106"

  strings:
    $s1  = "var Mj = true  , LXst = CMK[7] + CMK[9] + CMK[11];" fullword ascii
    $s2  = "return NSHxCjS[0] + NSHxCjS[2] + NSHxCjS[4] + \".F\" + NSHxCjS[7] + NSHxCjS[9] + NSHxCjS[12] + NSHxCjS[14];" fullword ascii
    $s3  = "eUxmC.open(fIPLx,gbrTR,false);" fullword ascii
    $s4  = "var CMK = (\"2.XMLHTTP uZqjhTt EUGIN XML ream St EJwyhBmG AD gFEPmpE O lOqD D\").split(\" \");" fullword ascii
    $s5  = "var NSHxCjS = \"Sc CvFodgG r glLtEdasD ipting EKIeZPV YuI ile FJVLxCQsuSyTxn System fO xVRtK Obj EZnsww ect pcEDJlY\".split(\" " ascii
    $s6  = "return RGrPNNc(qZ,gDUnL[279-273]+gDUnL[532-525]+gDUnL[616-608]);" fullword ascii
    $s7  = "if (DcYSm > 128879-657){return true;} else {return false;}" fullword ascii
    $s8  = "return oanji.status;" fullword ascii
    $s9  = "function QNaJcxsPr(Yplwnvkmsvk) {" fullword ascii
    $s10 = "function xvoy(Mxxge,akSnm) {" fullword ascii
    $s11 = "function fSKu(CXXqr) {" fullword ascii
    $s12 = "function QyTZ(eUxmC,gbrTR,fIPLx) {" fullword ascii
    $s13 = "function vkcvmAJ(kYHd) {" fullword ascii
    $s14 = "if (qbEdO == 784-584){return true;} else {return false;}" fullword ascii
    $s15 = "function ArSt(JBeuD) {" fullword ascii
    $s16 = "function BZbK(DcYSm) {" fullword ascii
    $s17 = "return lEP.size;" fullword ascii
    $s18 = "if (q >= oNKbt.length) {break;}" fullword ascii
    $s19 = "return sEhux;" fullword ascii
    $s20 = "return YsHg.ExpandEnvironmentStrings(cuXiZ);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}