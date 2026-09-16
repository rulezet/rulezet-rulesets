rule sig_20160411_6f722ad0babf24496e44890e21d87bd6 {
  meta:
    description = "datamaliciousorder - file 20160411_6f722ad0babf24496e44890e21d87bd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52858f6f6eb937c3c1888afc02a57993666aa04a5b709bf576c8e04c5acbf307"

  strings:
    $s1  = "var kA = true  , tcvZ = biF[7] + biF[9] + biF[11];" fullword ascii
    $s2  = "return TuQTwHG[0] + TuQTwHG[2] + TuQTwHG[4] + \".F\" + TuQTwHG[7] + TuQTwHG[9] + TuQTwHG[12] + TuQTwHG[14];" fullword ascii
    $s3  = "var biF = (\"2.XMLHTTP VlmpMil GreZb XML ream St qLXGMkyX AD BrFmdHO O vccl D\").split(\" \");" fullword ascii
    $s4  = "CjOc.open(wSRGn,UoPUv,false);" fullword ascii
    $s5  = "function yuZBF(KynowIEB,nPnc) {" fullword ascii
    $s6  = "function vflCx(jWE,bDHcl) {" fullword ascii
    $s7  = "return MOzIckw[0];" fullword ascii
    $s8  = "function LxHkKnVUF(EKSFbjEarKU) {" fullword ascii
    $s9  = "return MloPi.status;" fullword ascii
    $s10 = "if(u>=f.length) {break;}" fullword ascii
    $s11 = "return Bdsmv;" fullword ascii
    $s12 = "function zrOQhIC(YNeT) {" fullword ascii
    $s13 = "return jWE[aTDi[0]](bDHcl);" fullword ascii
    $s14 = "if (L >= hguMI.length) {break;}" fullword ascii
    $s15 = "function Vdyk(hguMI) {" fullword ascii
    $s16 = "function eZqrl(KIHwsU) {" fullword ascii
    $s17 = "function kJdG(ZPaVL) {" fullword ascii
    $s18 = "function pzCfPvJF(mie) {" fullword ascii
    $s19 = "if (WOOFe == 923-723){return true;} else {return false;}" fullword ascii
    $s20 = "function LaFY(ziEpR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}