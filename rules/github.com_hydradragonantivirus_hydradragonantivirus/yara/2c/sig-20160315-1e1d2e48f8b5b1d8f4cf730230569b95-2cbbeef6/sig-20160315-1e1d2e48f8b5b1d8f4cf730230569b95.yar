rule sig_20160315_1e1d2e48f8b5b1d8f4cf730230569b95 {
  meta:
    description = "datamaliciousorder - file 20160315_1e1d2e48f8b5b1d8f4cf730230569b95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9620b02eb6cf35f14ce930f8e4bfbe73a0c8eeb470cbe822498aac646f3b5a87"

  strings:
    $s1  = "return yHDVGsA[0] + yHDVGsA[2] + yHDVGsA[4] + \".F\" + yHDVGsA[7] + yHDVGsA[9] + yHDVGsA[12] + yHDVGsA[14];" fullword ascii
    $s2  = "var Np = true  , TZaM = WJS[7] + WJS[9] + WJS[11];" fullword ascii
    $s3  = "rFYdP.open(MtnaA,eMVCQ,false);" fullword ascii
    $s4  = "var yHDVGsA = gOHfz(\"Sc yzeheyP r IWaCQmPwX ipting vlfzbxY TRy ile MCrGwTSvzUKjJL System Bj dUkaQ Obj WAHjIa ect lqHcLvj IGLoq" ascii
    $s5  = "var WJS = (\"2.XMLHTTP xXrboEV AxGMi XML ream St vZaJMorh AD fsZuMXd O vNKh D\").split(\" \");" fullword ascii
    $s6  = "var yHDVGsA = gOHfz(\"Sc yzeheyP r IWaCQmPwX ipting vlfzbxY TRy ile MCrGwTSvzUKjJL System Bj dUkaQ Obj WAHjIa ect lqHcLvj IGLoq" ascii
    $s7  = "if(D>=h.length) {break;}" fullword ascii
    $s8  = "return NmLPyd.position=394-394;" fullword ascii
    $s9  = "function gOHfz(oNu,iRiFb) {" fullword ascii
    $s10 = "function bCuf(rFYdP,eMVCQ,MtnaA) {" fullword ascii
    $s11 = "function lsbMqlFRw(SiwUwujhYNW) {" fullword ascii
    $s12 = "function gzEX(PbMZD) {" fullword ascii
    $s13 = "return WTbc.responseBody;" fullword ascii
    $s14 = "function fjFrMlb(FlUP,lqnzZ) {" fullword ascii
    $s15 = "function mTue(ViDwC) {" fullword ascii
    $s16 = "return fjFrMlb(DE,Msklk[500-494]+Msklk[620-613]+Msklk[697-689]);" fullword ascii
    $s17 = "function ZEOc(AqiSb) {" fullword ascii
    $s18 = "return FlUP.ExpandEnvironmentStrings(lqnzZ);" fullword ascii
    $s19 = "JXh = D; break; " fullword ascii
    $s20 = "if (AqiSb > 169384-671){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}