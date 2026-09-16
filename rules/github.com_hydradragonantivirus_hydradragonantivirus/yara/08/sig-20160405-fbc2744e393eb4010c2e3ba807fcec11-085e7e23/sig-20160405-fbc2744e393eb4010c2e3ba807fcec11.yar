rule sig_20160405_fbc2744e393eb4010c2e3ba807fcec11 {
  meta:
    description = "datamaliciousorder - file 20160405_fbc2744e393eb4010c2e3ba807fcec11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9700880b30ad3af1e6f57adf6c7291576dc4d5954683514c9139e98568dc8c31"

  strings:
    $s1  = "return ZmIYyYY[0] + ZmIYyYY[2] + ZmIYyYY[4] + \".F\" + ZmIYyYY[7] + ZmIYyYY[9] + ZmIYyYY[12] + ZmIYyYY[14];" fullword ascii
    $s2  = "var oka = LhHp(Yirn + \"B.\" + xHp[5]+(685701, xHp[4]));" fullword ascii
    $s3  = "var Rz = true  , Yirn = xHp[7] + xHp[9] + xHp[11];" fullword ascii
    $s4  = "var xHp = (\"2.XMLHTTP UNTbKJZ Wamje XML ream St KJpmiufb AD brNqsai O Gsay D\").split(\" \");" fullword ascii
    $s5  = "Bgxg.open(BTCHz,GaKPr,false);" fullword ascii
    $s6  = "function nFREK(RUl,FycHG) {" fullword ascii
    $s7  = "return FDKnW;" fullword ascii
    $s8  = "function JSmp(CcEle) {" fullword ascii
    $s9  = "return sItj[dtqhsq[0]];" fullword ascii
    $s10 = "function AeqWjGSz(QcL) {" fullword ascii
    $s11 = "function NZrs(WmJpe) {" fullword ascii
    $s12 = "meS = J; break; " fullword ascii
    $s13 = "return cDmrZNY(fm,Dtxhw[930-924]+Dtxhw[149-142]+Dtxhw[854-846]);" fullword ascii
    $s14 = "var BIqHUGi = \"CxNDgr*UWn*pt.S\"+\"hell*JLuybQf*Scri*\";" fullword ascii
    $s15 = "function Gtto(CcxNV) {" fullword ascii
    $s16 = "if (DrYWW > 194975-214){return true;} else {return false;}" fullword ascii
    $s17 = "if(J>=e.length) {break;}" fullword ascii
    $s18 = "return AujteFk[0];" fullword ascii
    $s19 = "function LhHp(cQuHE) {" fullword ascii
    $s20 = "function LPgz(DrYWW) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}