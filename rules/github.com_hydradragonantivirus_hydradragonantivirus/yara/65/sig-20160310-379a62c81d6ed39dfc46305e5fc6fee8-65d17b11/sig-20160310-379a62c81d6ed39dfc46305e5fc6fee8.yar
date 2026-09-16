rule sig_20160310_379a62c81d6ed39dfc46305e5fc6fee8 {
  meta:
    description = "datamaliciousorder - file 20160310_379a62c81d6ed39dfc46305e5fc6fee8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25fc00bc8ee3500e93e319cf634dd64dfb5a810a3f4870ffe94f74bc937482fe"

  strings:
    $s1  = "var yg = true  , XpCS = Xzl[7] + Xzl[9] + Xzl[11];" fullword ascii
    $s2  = "return PAThqdS[0] + PAThqdS[2] + PAThqdS[4] + \".F\" + PAThqdS[7] + PAThqdS[9] + PAThqdS[12] + PAThqdS[14];" fullword ascii
    $s3  = "var Xzl = (\"2.XMLHTTP iigqccM dICqQ XML ream St lLkmcqrv AD xYNevHr O QiCg D\").split(\" \");" fullword ascii
    $s4  = "hbsBJ.open(PChJS,AxIDY,false);" fullword ascii
    $s5  = "var PAThqdS = \"Sc YuQpweo r MaxzvDKQC ipting SYwCpsd shr ile kEmakutIVQEtVp System wV RrDPC Obj RuHVgx ect RrrrxIP\".split(\" " ascii
    $s6  = "function bpwU(trPap) {" fullword ascii
    $s7  = "function zEsP(hbsBJ,AxIDY,PChJS) {" fullword ascii
    $s8  = "if(E>=I.length) {break;}" fullword ascii
    $s9  = "function ULFc(wCuRt) {" fullword ascii
    $s10 = "return LZoJsou" fullword ascii
    $s11 = "if (wCuRt > 169290-486){return true;} else {return false;}" fullword ascii
    $s12 = "function bGtt(Iqqin,cYXBK) {" fullword ascii
    $s13 = "return ngEuBvz(gv,MktLI[762-756]+MktLI[693-686]+MktLI[919-911]);" fullword ascii
    $s14 = "OUW = E; break; " fullword ascii
    $s15 = "function nuCt(CRAyD) {" fullword ascii
    $s16 = "return afGA.ExpandEnvironmentStrings(pdAjX);" fullword ascii
    $s17 = "return nlpfuC.position=897-897;" fullword ascii
    $s18 = "function ngEuBvz(afGA,pdAjX) {" fullword ascii
    $s19 = "if (wcjxk == 1181-981){return true;} else {return false;}" fullword ascii
    $s20 = "function gLVwgZOhf(JRgsUAVHYhz) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}