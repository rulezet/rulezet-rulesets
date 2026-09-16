rule sig_20160309_8817d440ccd201d424a4a2e9c421ed31 {
  meta:
    description = "datamaliciousorder - file 20160309_8817d440ccd201d424a4a2e9c421ed31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faf68de0421974acc9c1d4201f1d1e4b647f7ccaaf41779d26b760729e4d1903"

  strings:
    $s1  = "return GooWJIz[0] + GooWJIz[2] + GooWJIz[4] + \".F\" + GooWJIz[7] + GooWJIz[9] + GooWJIz[12] + GooWJIz[14];" fullword ascii
    $s2  = "var YB = true  , cXZX = qqT[7] + qqT[9] + qqT[11];" fullword ascii
    $s3  = "var qqT = (\"2.XMLHTTP HzAGIqS XbEIm XML ream St naKjGkua AD yQlvOVn O aGXL D\").split(\" \");" fullword ascii
    $s4  = "mdiZe.open(pcZVb,PeajG,false);" fullword ascii
    $s5  = "var GooWJIz = \"Sc ASRysiH r lPqUQiXsM ipting FoUkYCL hHO ile aesqEnBWvBknUm System aU iLqkq Obj DYgFuM ect ZGiZHCK\".split(\" " ascii
    $s6  = "function KNUM(DsFWq,WOMMu) {" fullword ascii
    $s7  = "function JnHvmgA(vnuJ,xHIOu) {" fullword ascii
    $s8  = "if (UKVOT > 188797-866){return true;} else {return false;}" fullword ascii
    $s9  = "function lEIA(FhmzF) {" fullword ascii
    $s10 = "function HWxG(Cjucx) {" fullword ascii
    $s11 = "function kLxv(UKVOT) {" fullword ascii
    $s12 = "return vnuJ.ExpandEnvironmentStrings(xHIOu);" fullword ascii
    $s13 = "return new ActiveXObject(ctCFoj);" fullword ascii
    $s14 = "function dTNI(fndFt) {" fullword ascii
    $s15 = "return ZdsfZMt" fullword ascii
    $s16 = "return UuYy.responseBody;" fullword ascii
    $s17 = "function wmkAATRR(mWs) {" fullword ascii
    $s18 = "function LZDl(fhFeP) {" fullword ascii
    $s19 = "function dFCxHwjyH(VRkapBfiARE) {" fullword ascii
    $s20 = "return JnHvmgA(Iv,EjLum[171-165]+EjLum[553-546]+EjLum[273-265]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}