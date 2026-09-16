rule sig_20160411_8fa53443af441597556f1893c52797bd {
  meta:
    description = "datamaliciousorder - file 20160411_8fa53443af441597556f1893c52797bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07a462db8a9cab36bd20267fcf970ebc9d8564c50ce74dfb967cd2c25ebf6909"

  strings:
    $s1  = "return XgrLwuF[0] + XgrLwuF[2] + XgrLwuF[4] + \".F\" + XgrLwuF[7] + XgrLwuF[9] + XgrLwuF[12] + XgrLwuF[14];" fullword ascii
    $s2  = "var Iz = true  , JvSi = xpy[7] + xpy[9] + xpy[11];" fullword ascii
    $s3  = "pOkJ.open(dpRaC,hQRSG,false);" fullword ascii
    $s4  = "var xpy = (\"2.XMLHTTP EmgEdEf cmCOz XML ream St PkLDuBHu AD mFJYHfz O baER D\").split(\" \");" fullword ascii
    $s5  = "return \"hAbbPisCmnWhrj\";" fullword ascii
    $s6  = "function JytHi(xiH,QBSjw) {" fullword ascii
    $s7  = "function iVNhb(xXOZud) {" fullword ascii
    $s8  = "return AkoZE;" fullword ascii
    $s9  = "function YAlzTlXn(OjYM) {" fullword ascii
    $s10 = "function pxsh(pPiPv,lDIpY) {" fullword ascii
    $s11 = "return mQAB[zzdSAlm[0]+zzdSAlm[1]];" fullword ascii
    $s12 = "return new ActiveXObject(qQEP);" fullword ascii
    $s13 = "if (gVKTl > 169842-483){return true;} else {return false;}" fullword ascii
    $s14 = "function VzLBLv(VPYM,XeSUXY) {" fullword ascii
    $s15 = "function VnmSRLlFa(dQuVF) {" fullword ascii
    $s16 = "return rgQVGJK[0];" fullword ascii
    $s17 = "return xtOXgES(aA,fvypSD+rIadA[673-665]);" fullword ascii
    $s18 = "function SJbp(Ayzew,hQRSG,dpRaC) {" fullword ascii
    $s19 = "function QzpNXjPG(VIk) {" fullword ascii
    $s20 = "return cnLhQtk;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}