rule sig_20160313_201252e73564ec5e208c0595cb459491 {
  meta:
    description = "datamaliciousorder - file 20160313_201252e73564ec5e208c0595cb459491.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d39c45b96b8f8368fa916630a880c47336148e72c7bc8fe1855a3ffbe42e0359"

  strings:
    $s1  = "return UMsqNPQ[0] + UMsqNPQ[2] + UMsqNPQ[4] + \".F\" + UMsqNPQ[7] + UMsqNPQ[9] + UMsqNPQ[12] + UMsqNPQ[14];" fullword ascii
    $s2  = "var gG = true  , ZNaq = TUA[7] + TUA[9] + TUA[11];" fullword ascii
    $s3  = "var UMsqNPQ = \"Sc vmboOPY r OzPMrBMgx ipting fjsQsLj tGn ile uHbCZsFSJsKNni System iS atRsB Obj LQzkye ect EGLdMdr\".split(\" " ascii
    $s4  = "YwcIA.open(eHEYy,dYuVT,false);" fullword ascii
    $s5  = "var TUA = (\"2.XMLHTTP rstPtcs mutXM XML ream St XPFYwrES AD ELcpQUf O vhmf D\").split(\" \");" fullword ascii
    $s6  = "function rDvr(LdYpR) {" fullword ascii
    $s7  = "function oWSxWUtW() {" fullword ascii
    $s8  = "function IhElWUD(YHah,xEcqq) {" fullword ascii
    $s9  = "function HEAJ(SaMZC) {" fullword ascii
    $s10 = "function Bedp(fyzwn,zadJt) {" fullword ascii
    $s11 = "if (bqqii > 190493-705){return true;} else {return false;}" fullword ascii
    $s12 = "return ySfIi;" fullword ascii
    $s13 = "function Sobyp(aZviLH) {" fullword ascii
    $s14 = "if (LwuCO == 694-494){return true;} else {return false;}" fullword ascii
    $s15 = "function lbKt(bqqii) {" fullword ascii
    $s16 = "return IhElWUD(pB,KpzeS[365-359]+KpzeS[926-919]+KpzeS[341-333]);" fullword ascii
    $s17 = "function wmsn(LwuCO) {" fullword ascii
    $s18 = "return EemQkmy" fullword ascii
    $s19 = "return aZviLH.position=417-417;" fullword ascii
    $s20 = "function lOzI(pppRx) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}