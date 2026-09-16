rule sig_20160324_0f55bc911dad28e2689e78cb16df324d {
  meta:
    description = "datamaliciousorder - file 20160324_0f55bc911dad28e2689e78cb16df324d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18d952a5c9de3e619ffe3bfb70d995e393cb51eb3a29aee39dfc7a8a5155a22f"

  strings:
    $s1  = "return WScript.CreateObject(dLkaw);" fullword ascii
    $s2  = "return CqlMDWv[0] + CqlMDWv[2] + CqlMDWv[4] + \".F\" + CqlMDWv[7] + CqlMDWv[9] + CqlMDWv[12] + CqlMDWv[14];" fullword ascii
    $s3  = "var yD = true  , qQYq = DUL[7] + DUL[9] + DUL[11];" fullword ascii
    $s4  = "if (mCMDT > 177665-105){return true;} else {return false;}" fullword ascii
    $s5  = "VDYT.open(vglZN,oDyzR,false);" fullword ascii
    $s6  = "function IAXf(mCMDT) {" fullword ascii
    $s7  = "var DUL = (\"2.XMLHTTP BCzuKHd TkreH XML ream St kfEGuSlf AD nuzzKBb O rlHs D\").split(\" \");" fullword ascii
    $s8  = "var CqlMDWv = advry(tMenPHCuQp+\" \"+\"System gj GyYuW Obj PQdinv ect vcUZBvP ImUCX\", \" \");" fullword ascii
    $s9  = "if (P >= lKOdQ.length) {break;}" fullword ascii
    $s10 = "function DpWZrXMdU(WgHWy) {" fullword ascii
    $s11 = "function mcVS(dLkaw) {" fullword ascii
    $s12 = "return FUvM.ExpandEnvironmentStrings(FwgAi);" fullword ascii
    $s13 = "function TijqwXb(FUvM,FwgAi) {" fullword ascii
    $s14 = "var wGouSCn = \"dsxhUy*drw*pt.S\"+\"hell*SJKoMsk*Scri*\";" fullword ascii
    $s15 = "function tJQK(yGdvN) {" fullword ascii
    $s16 = "return TijqwXb(El,mqZJJ[147-141]+mqZJJ[174-167]+mqZJJ[320-312]);" fullword ascii
    $s17 = "function nCkNBFQF(ZhQ) {" fullword ascii
    $s18 = "function LHgRX(egSifZ) {" fullword ascii
    $s19 = "function hhzs(ZVuMw) {" fullword ascii
    $s20 = "function advry(yjO,cgslS) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}