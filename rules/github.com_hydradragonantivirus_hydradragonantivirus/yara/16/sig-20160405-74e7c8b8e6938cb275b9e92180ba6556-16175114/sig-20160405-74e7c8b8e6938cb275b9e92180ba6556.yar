rule sig_20160405_74e7c8b8e6938cb275b9e92180ba6556 {
  meta:
    description = "datamaliciousorder - file 20160405_74e7c8b8e6938cb275b9e92180ba6556.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51d11929598580f21b04b15cc8774ce1695cbc70342553d55a120df6f5b35ebe"

  strings:
    $s1  = "return iFupyQg[0] + iFupyQg[2] + iFupyQg[4] + \".F\" + iFupyQg[7] + iFupyQg[9] + iFupyQg[12] + iFupyQg[14];" fullword ascii
    $s2  = "var HQ = true  , KbcH = MzM[7] + MzM[9] + MzM[11];" fullword ascii
    $s3  = "RdoI.open(VZuUP,ZYCxD,false);" fullword ascii
    $s4  = "var MzM = (\"2.XMLHTTP aGsJzeR OoHhF XML ream St EiGKJLcs AD kMDnBWQ O NPFu D\").split(\" \");" fullword ascii
    $s5  = "var wLAmvEP = \"KRffYz*aeL*pt.S\"+\"hell*DCxmKCK*Scri*\";" fullword ascii
    $s6  = "function nwRlO(Ygj,bnpuc) {" fullword ascii
    $s7  = "return SVIweQy(Ou,DfEwf[507-501]+DfEwf[493-486]+DfEwf[549-541]);" fullword ascii
    $s8  = "function LWwn(NZMYW,hILVa) {" fullword ascii
    $s9  = "function pMfs(dvGxy) {" fullword ascii
    $s10 = "function UQwSK(AHgWTg) {" fullword ascii
    $s11 = "return LCko;" fullword ascii
    $s12 = "function oJGltgCDW(mLxiU) {" fullword ascii
    $s13 = "return new ActiveXObject(dDfX);" fullword ascii
    $s14 = "function jYKx(vUFbL) {" fullword ascii
    $s15 = "function SVIweQy(WPtT,JWpci) {" fullword ascii
    $s16 = "if (vUFbL > 152760-343){return true;} else {return false;}" fullword ascii
    $s17 = "function xIXlO(fzAEpTcl,JTFM) {" fullword ascii
    $s18 = "function egKh(nlZnM) {" fullword ascii
    $s19 = "return moHw[aZSLYq[0]];" fullword ascii
    $s20 = "ncK = L; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}