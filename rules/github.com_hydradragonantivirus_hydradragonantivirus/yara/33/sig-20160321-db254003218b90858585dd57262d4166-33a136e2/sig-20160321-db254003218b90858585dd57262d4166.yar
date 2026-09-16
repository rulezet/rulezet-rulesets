rule sig_20160321_db254003218b90858585dd57262d4166 {
  meta:
    description = "datamaliciousorder - file 20160321_db254003218b90858585dd57262d4166.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8967a79d9ded51a5b2f30340a3afcc8e11f4b023df6aaea860df1e8fd2c28af1"

  strings:
    $s1  = "return WScript.CreateObject(FBojC);" fullword ascii
    $s2  = "return eThHyKa[0] + eThHyKa[2] + eThHyKa[4] + \".F\" + eThHyKa[7] + eThHyKa[9] + eThHyKa[12] + eThHyKa[14];" fullword ascii
    $s3  = "var Zm = true  , GGXm = VWh[7] + VWh[9] + VWh[11];" fullword ascii
    $s4  = "var VWh = (\"2.XMLHTTP gMvQCsc LNgVs XML ream St TTDCwUFB AD byHyZKI O jPwI D\").split(\" \");" fullword ascii
    $s5  = "if(f>=W.length) {break;}" fullword ascii
    $s6  = "function QBdT(wIoSw) {" fullword ascii
    $s7  = "function Pabi(nVxPe) {" fullword ascii
    $s8  = "function mffC(NpiyG) {" fullword ascii
    $s9  = "function spQl(UlqRo,ztqVz) {" fullword ascii
    $s10 = "function cNmooJMKR(AHpSX) {" fullword ascii
    $s11 = "return pRnV[sMrlaA[0]];" fullword ascii
    $s12 = "if (NpiyG > 171825-976){return true;} else {return false;}" fullword ascii
    $s13 = "return CBSo.ExpandEnvironmentStrings(QTPoP);" fullword ascii
    $s14 = "function kGhHAHd(CBSo,QTPoP) {" fullword ascii
    $s15 = "return vcEOB.status;" fullword ascii
    $s16 = "function XnMQ(rxYsT) {" fullword ascii
    $s17 = "return new ActiveXObject(VZQwto);" fullword ascii
    $s18 = "function jTGH(FBojC) {" fullword ascii
    $s19 = "return ROLttU.position=222-222;" fullword ascii
    $s20 = "function eyzaoWia(XNK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}