rule sig_20160404_6a1be9c09e54298f400933006eb62779 {
  meta:
    description = "datamaliciousorder - file 20160404_6a1be9c09e54298f400933006eb62779.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a9bfac3617ba87aae0533bd86756f9a61aba3b3260dcbd3f652454f70b9263b"

  strings:
    $s1  = "return qFYbpXQ[0] + qFYbpXQ[2] + qFYbpXQ[4] + \".F\" + qFYbpXQ[7] + qFYbpXQ[9] + qFYbpXQ[12] + qFYbpXQ[14];" fullword ascii
    $s2  = "var ZZ = true  , finm = VIR[7] + VIR[9] + VIR[11];" fullword ascii
    $s3  = "var qFYbpXQ = xashc(FRqXDpBNRi+\" \"+\"System tq vObFD Obj pGurKK ect GbudJsM aDqEx\", \" \");" fullword ascii
    $s4  = "qbpN.open(yubqB,ULOxH,false);" fullword ascii
    $s5  = "var VIR = (\"2.XMLHTTP BEhStby hgDyH XML ream St cGsKOTsL AD diIhvJu O XenR D\").split(\" \");" fullword ascii
    $s6  = "function hdHYjcjNP(vQjQD) {" fullword ascii
    $s7  = "if (j >= rCYeL.length) {break;}" fullword ascii
    $s8  = "return \"uzJmjaqhDAeMtE\";" fullword ascii
    $s9  = "return new ActiveXObject(CLcx);" fullword ascii
    $s10 = "function aPjYHrd(XrOb,expWY) {" fullword ascii
    $s11 = "TuH = V; break; " fullword ascii
    $s12 = "return nXY.size;" fullword ascii
    $s13 = "function nnXf(xOTEh) {" fullword ascii
    $s14 = "function owMEnBnY(nXY) {" fullword ascii
    $s15 = "function REDNA(uIJXpJSY,uqbO) {" fullword ascii
    $s16 = "return zFac[hzWQws[0]];" fullword ascii
    $s17 = "return xOTEh.status;" fullword ascii
    $s18 = "return aPjYHrd(bk,JfATx[584-578]+JfATx[590-583]+JfATx[166-158]);" fullword ascii
    $s19 = "if (btvmW == 398-198){return true;} else {return false;}" fullword ascii
    $s20 = "function QmkW(zaXgN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}