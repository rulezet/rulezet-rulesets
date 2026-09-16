rule sig_20160322_9bcddd4613b5fb67168bf10bacd08152 {
  meta:
    description = "datamaliciousorder - file 20160322_9bcddd4613b5fb67168bf10bacd08152.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73457da32c43b89dec6c22e3f85360cc807b57a588103ec6ba2da8f52f0bfe28"

  strings:
    $s1  = "return WScript.CreateObject(mZXID);" fullword ascii
    $s2  = "return DBQIKcB[0] + DBQIKcB[2] + DBQIKcB[4] + \".F\" + DBQIKcB[7] + DBQIKcB[9] + DBQIKcB[12] + DBQIKcB[14];" fullword ascii
    $s3  = "var mT = true  , Xehg = aqi[7] + aqi[9] + aqi[11];" fullword ascii
    $s4  = "krTH.open(ImdCM,GdexQ,false);" fullword ascii
    $s5  = "var aqi = (\"2.XMLHTTP kjWOZtT LFQIZ XML ream St FXabMQMM AD jDxIiJg O rWpW D\").split(\" \");" fullword ascii
    $s6  = "var DBQIKcB = XLjnT(rbDDjKPHEw+\" \"+\"System eZ WvcCr Obj lYRvdz ect aZZBGbX wSUDA\", \" \");" fullword ascii
    $s7  = "function WVulP(Ymjshi) {" fullword ascii
    $s8  = "function qyEu(GCCBp,GdexQ,ImdCM) {" fullword ascii
    $s9  = "function YGEB(QFHIb) {" fullword ascii
    $s10 = "function UddI(hkXdI,tusvb) {" fullword ascii
    $s11 = "return new ActiveXObject(RsXnTo);" fullword ascii
    $s12 = "function EUeC(Irgtg,UAFTO) {" fullword ascii
    $s13 = "function tFjU(jjAmq) {" fullword ascii
    $s14 = "function wPRd(PzQPW) {" fullword ascii
    $s15 = "function yFLucBM(Bavo) {" fullword ascii
    $s16 = "function LcNDCuZJl(cGicHCByTcG) {" fullword ascii
    $s17 = "function pjXz(OPHbC) {" fullword ascii
    $s18 = "if (rSqcJ > 197048-368){return true;} else {return false;}" fullword ascii
    $s19 = "return QlP.size;" fullword ascii
    $s20 = "function UxXX(mZXID) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}