rule sig_20160309_1021d9fc13d3556febba63947348c9c5 {
  meta:
    description = "datamaliciousorder - file 20160309_1021d9fc13d3556febba63947348c9c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8199c2cce80dec75f925fe788f943722ce21be3f7a29eb1ea66c2df38f5221bb"

  strings:
    $s1  = "var Qh = true  , gAmi = CHc[7] + CHc[9] + CHc[11];" fullword ascii
    $s2  = "return jcjpOkL[0] + jcjpOkL[2] + jcjpOkL[4] + \".F\" + jcjpOkL[7] + jcjpOkL[9] + jcjpOkL[12] + jcjpOkL[14];" fullword ascii
    $s3  = "var jcjpOkL = \"Sc hNuBrQn r sfXYrzrSE ipting XCLxKPc ZPK ile XZMGkrYuwmVmYf System Ti yAKkI Obj prTFYa ect ArzHAWO\".split(\" " ascii
    $s4  = "QEwtT.open(wrNce,wDahl,false);" fullword ascii
    $s5  = "var CHc = (\"2.XMLHTTP djtUtnO wkaOc XML ream St KaXpJGbb AD jLuPGVQ O bnIN D\").split(\" \");" fullword ascii
    $s6  = "return qaVpgxf(WL,xZTvJ[915-909]+xZTvJ[543-536]+xZTvJ[672-664]);" fullword ascii
    $s7  = "function iVavqlkQ(fnMON,yksEbr) {" fullword ascii
    $s8  = "function QPsNvfQK() {" fullword ascii
    $s9  = "function otBQ(enjxI) {" fullword ascii
    $s10 = "function LoCNMerjk(ManLZ,KYJlq,QygSC,xyRj) {" fullword ascii
    $s11 = "function mveV(ePKex) {" fullword ascii
    $s12 = "return eqvcE;" fullword ascii
    $s13 = "function ZLji(zVsOc) {" fullword ascii
    $s14 = "function IgehQIT(zKji) {" fullword ascii
    $s15 = "return new ActiveXObject(uDmraW);" fullword ascii
    $s16 = "return ZXL.size;" fullword ascii
    $s17 = "if (o >= GzSWy.length) {break;}" fullword ascii
    $s18 = "function STOd(QEwtT,wDahl,wrNce) {" fullword ascii
    $s19 = "function dUpma(uDmraW) {" fullword ascii
    $s20 = "function YApS(PEBFy,TyvqR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}