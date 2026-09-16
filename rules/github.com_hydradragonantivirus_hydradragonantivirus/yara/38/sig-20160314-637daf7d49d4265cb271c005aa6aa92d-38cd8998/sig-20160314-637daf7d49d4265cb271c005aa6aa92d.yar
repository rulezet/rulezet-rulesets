rule sig_20160314_637daf7d49d4265cb271c005aa6aa92d {
  meta:
    description = "datamaliciousorder - file 20160314_637daf7d49d4265cb271c005aa6aa92d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c948d5f2b5d582ef8755c9e3cfaea29fb7db844350456cef8a61bae9fddfa23a"

  strings:
    $s1  = "var Gl = true  , dUQa = KBI[7] + KBI[9] + KBI[11];" fullword ascii
    $s2  = "return UJMXwmJ[0] + UJMXwmJ[2] + UJMXwmJ[4] + \".F\" + UJMXwmJ[7] + UJMXwmJ[9] + UJMXwmJ[12] + UJMXwmJ[14];" fullword ascii
    $s3  = "cZMKm.open(pfQsH,CDNFe,false);" fullword ascii
    $s4  = "var KBI = (\"2.XMLHTTP DtjvsnP HJrjH XML ream St ARGaWgBr AD pxcwctX O KfdR D\").split(\" \");" fullword ascii
    $s5  = "function xHHB(LxAzB) {" fullword ascii
    $s6  = "function uxPA(KYNKj,SWJcP) {" fullword ascii
    $s7  = "function wuzPX(ZAwQZF) {" fullword ascii
    $s8  = "function dREeKffZC() {" fullword ascii
    $s9  = "function aDpu(YbimO) {" fullword ascii
    $s10 = "return hYao.responseBody;" fullword ascii
    $s11 = "function zeYV(DyPyP) {" fullword ascii
    $s12 = "function/*uaxw*/aUGWYqow(glakY,axrMPg) {" fullword ascii
    $s13 = "if (DyPyP == 389-189){return true;} else {return false;}" fullword ascii
    $s14 = "return taSWW;" fullword ascii
    $s15 = "return kRbg.ExpandEnvironmentStrings(Azlug);" fullword ascii
    $s16 = "function saMWDwz(hYao) {" fullword ascii
    $s17 = "function LSeA(yIrwt) {" fullword ascii
    $s18 = "glakY[bXcr[271-271]](axrMPg);" fullword ascii
    $s19 = "function kKWPfAC(kRbg,Azlug) {" fullword ascii
    $s20 = "return new ActiveXObject(ZAwQZF);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}