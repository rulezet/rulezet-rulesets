rule sig_20160321_41bd285ab82bbca95a2e8b61583d3a8e {
  meta:
    description = "datamaliciousorder - file 20160321_41bd285ab82bbca95a2e8b61583d3a8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec30dd656cabb85a8c3bb986897c436a822e3f6c4e9d84bae2f4159acb984d69"

  strings:
    $s1  = "function X0(z1){return z1;};var o0 = \"LD2lw\";var ndG = \"8162\";var crDGR = \"1\\x3836\";var huO = o0[\"c\\x68arA\\x74\"](2);f" ascii
    $s2  = "HuI(){return Bo;}()) + ch + wOHZL + sRT(J); YTGi = UM(); m = WScript[K + Iasb(bmY) + vFKlN + v(bLfJ) + a(tMvv)](YTGi); var jiiqL" ascii
    $s3  = "c\";var vFKlN = \"teO\";var bmY = \"ea\";var K = \"\\x43r\";var WD = function VCpY() {return WScript[tVf(K) + (function zw(){ret" ascii
    $s4  = "(Bmw) + (function grNe(){return YaJ;}()) + QFR(dNEc);};function Nw(LcH, hdx){return LcH - hdx;};function hjGId(){return oY(K) + " ascii
    $s5  = "ue;dpj = true;break;}}function BxJVS() {return VT && dpj;};if (BxJVS()){gGOnX = WD[inv + lWe(LN) + (function sNk(){return x;}())" ascii
    $s6  = "f(dor)] < 4 ) {WScript[(function PLy(){return Vogdb;}())](RX() * 10)};jiiqL = false;} catch(e){};}zCmcd = WScript[hjGId()]((func" ascii
    $s7  = "+ hokJp + (function UblQN(){return Q;}()) + (function LRxVG(){return P;}()) + wGCa]();WScript[Vogdb](RX());var pNpw = new this[(" ascii
    $s8  = "b(Q) + gh(P) + Jz(wGCa)]();WScript[Vogdb](RX());var pNpw = new this[(function YZ(){return pg;}())]();var si = pNpw[I + G(wVVWU) " ascii
    $s9  = "(ivXf) + rIQv(YX) + (function ezns(){return BlMXZ;}()) + (function dUrR(){return sPd;}()) + Ci + (function w2(){return IOMlB;}()" ascii
    $s10 = "}()) + (function DZTAL(){return vFKlN;}()) + (function tpff(){return bLfJ;}()) + tMvv](dxU + (function uSgJ(){return XgW;}()) + " ascii
    $s11 = "ion q0(){return gqu;}()) + a1(FAAS) + (function Ym(){return hs;}())] = 0;zCmcd[(function dMy(){return y;}()) + (function Y1(){re" ascii
    $s12 = "j) + tMdh + (function zEt(){return EK;}()) + (function aE(){return TEH;}()) + uIt(lAYe) + eSpz(Y2) + mNj(l0) + ZndZz + pBSM + YS" ascii
    $s13 = "function wJX(){return pg;}())]();var dTeX = pNpw[(function oj(){return I;}()) + (function T(){return wVVWU;}()) + (function a0()" ascii
    $s14 = "turn QiW;}()) + (function AVgk(){return XIiL;}()))]();zCmcd[eeyO + vVZV] = 1;zCmcd[Us + (function d0(){return z;}()) + (function" ascii
    $s15 = "xX) + lJ + (function yGDjm(){return Br;}()) + BpWT(kQh) + rc(SIjZI) + Xzq(aSvG) + YnSZJ(LJRJ) + (function SI(){return KHZF;}()) " ascii
    $s16 = "(function zw0(){return bmY;}()) + (function ndias(){return vFKlN;}()) + (function hz(){return bLfJ;}()) + DhgZw(tMvv);};function" ascii
    $s17 = " = true; while (jiiqL){try {m[F(QiW) + XIiL]((function Rf(){return Ld;}()), G0 + Wjzfv + (function qDpu(){return vo;}()) + gkr(D" ascii
    $s18 = "pCYk(UsqNO) + uul);}();function CTFa(IW){WD[f(rnY)](IW, 0, 0);};function UM(){return t + (function LEcm(){return v0;}()) + PanNS" ascii
    $s19 = "Q = Nw(dTeX, si);return Nw(e, gTMWQ);}var VT = false;var dpj = false;for (var yM = 0; yM < RX() * 1; yM++){if (A() != 0){VT = tr" ascii
    $s20 = " RX(){return 22;};function A(){var pNpw = new this[dIM(pg)]();var NgbR = pNpw[I + (function OvYo(){return wVVWU;}()) + hokJp + y" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}