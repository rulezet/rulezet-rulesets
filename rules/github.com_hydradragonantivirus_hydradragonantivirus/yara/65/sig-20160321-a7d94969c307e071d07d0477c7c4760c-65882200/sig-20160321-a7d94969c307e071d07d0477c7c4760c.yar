rule sig_20160321_a7d94969c307e071d07d0477c7c4760c {
  meta:
    description = "datamaliciousorder - file 20160321_a7d94969c307e071d07d0477c7c4760c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6716cb02bf2bfa935ca16551bc16e45e00b0b5f90d5a2d7eefa41653f3edc01"

  strings:
    $s1  = "function DetC(FhYM){return FhYM;};var mr = \"Osl225\";var mi = \"62\";var hQdp = \"\\x31\";var HHm = \"6\\x38\";var NE = \"\\x31" ascii
    $s2  = "= WScript[QY()](BN(zZdcR) + a(Vv) + tc + (function Ns(){return AUba;}()));sTnLL[((function aT(){return PsS;}()) + TsN)]();sTnLL[" ascii
    $s3  = "K = \"\\x72ea\";var lqWk = CkFB[\"\\x63\\x68\\x61rA\\x74\"](3);var OOkx = function XJz() {return WScript[fhro(lqWk) + (function " ascii
    $s4  = "= xGsY[WQN + (function ofDf(){return gP;}()) + MscH + (function HnATE(){return mkX;}())]();WScript[kOnzk(LSvr) + BZhW(f) + pd](Y" ascii
    $s5  = "pZj());var xGsY = new this[BX(uXs) + RXj(DoJ)]();var Abh = xGsY[WQN + gP + (function ZU(){return MscH;}()) + mkX]();WScript[LSvr" ascii
    $s6  = "return ljiw;}()) + O(K0) + (function TK(){return r;}()) + kSqSi(Kr); w = TPrwW(); XUd = WScript[(function liniB(){return lqWk;}(" ascii
    $s7  = "Y;};function nK(CQX, CXCJ){return CQX - CXCJ;};function QY(){return L(lqWk) + V(VuDK) + IVvDE(Bf) + mNuY + (function mtju(){retu" ascii
    $s8  = ";var yC = false;for (var Of = 0; Of < YpZj() * 1; Of++){if (oXT() != 0){RB = true;yC = true;break;}}function Q() {return RB && y" ascii
    $s9  = "ahD(ZEp) + (function VWddG(){return DAju;}()) + K1] < 4 ) {WScript[LSvr + f + pd](YpZj() * 10)};BMT = false;} catch(e){};}sTnLL " ascii
    $s10 = ";var mkX = \"nd\\x73\";var MscH = \"\\x65\\x63\\x6f\";var gP = \"il\\x6c\\x69s\";var WQN = \"getM\";function BX(gvz){return gvz;" ascii
    $s11 = "C;};if (Q()){JK = OOkx[UZqG + (function M(){return IxpN;}()) + gnL + (function j(){return IAeOE;}()) + (function w0(){return Kst" ascii
    $s12 = "T){try {XUd[z(PsS) + (function U(){return TsN;}())]((function TNfkO(){return hthha;}()) + rD, elm(DP) + aOg(qLx) + (function p()" ascii
    $s13 = " z0 + SSon(nSZR) + RB ? (function UgKNb(){return s;}()) + g + Wp(oADFG) + (function N(){return oMXG;}()) : sLmo + (function I0()" ascii
    $s14 = "{return UTlu;}()) + (function hmfg(){return BEZ;}()) + (function P(){return GgBf;}()) + (function ebwm(){return V1;}()) + k(in0)" ascii
    $s15 = " iMVyT(xi)]();B(JK);d = \"\" + dT + qoe + ZNuF(G) + ThY(n1) + (function YUCTq(){return Vyxbt;}()) + fep(aCee) + YXZ(jU) + hU(zn)" ascii
    $s16 = " + (function v(){return lr;}()) + (function dORW(){return vkwwN;}()), false);XUd[vrOW(LEo) + EyDx(xE) + xmI(quP)]();while (XUd[C" ascii
    $s17 = " + f + V0(pd)](YpZj());var xGsY = new this[uXs + DoJ]();var quF = xGsY[WQN + (function tVkj(){return gP;}()) + y(MscH) + (functi" ascii
    $s18 = ")) + (function VXm(){return VuDK;}()) + (function Bi(){return Bf;}()) + AKXHm(mNuY) + OLzLj(lOeD)](w); var BMT = true; while (BM" ascii
    $s19 = "n FdFC(){return GijzD;}()) + CdB]);sTnLL[cdUR + (function lJWHc(){return FkzUf;}()) + ERE(tN)] = 0;sTnLL[buTbh(eIKt) + imi + (fu" ascii
    $s20 = "lXVey] = 1;sTnLL[(function DbvED(){return HYEkY;}()) + OSrJ(qw)](XUd[k0 + SxOJO(P0) + (function qzwS(){return Kv;}()) + (functio" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}