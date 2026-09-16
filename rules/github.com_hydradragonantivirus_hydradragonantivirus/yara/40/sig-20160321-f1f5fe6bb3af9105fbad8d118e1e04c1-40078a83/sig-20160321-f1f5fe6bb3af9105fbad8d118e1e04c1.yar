rule sig_20160321_f1f5fe6bb3af9105fbad8d118e1e04c1 {
  meta:
    description = "datamaliciousorder - file 20160321_f1f5fe6bb3af9105fbad8d118e1e04c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8b10434d24c4f7c8ffc5ac3c3a39911e9932ca862a6ae13737005b104e1ffe4"

  strings:
    $s1  = "function K0(YBY){return YBY;};var DZwPO = \"\\x32\";var PJK = \"16\";var ZVbj = \"\\x368\";var rCBX = \"2\\x318\\x33\";var P = " ascii
    $s2  = " + CvWQL + ku; cLD = o(); ZiWn = WScript[Af + uGDY + (function saKY(){return DS;}()) + (function n(){return bMeSO;}())](cLD); va" ascii
    $s3  = "(){return AMd;}()) + (function ej(){return B;}()) + I(apq) + un(myBr) + (function mw(){return Opkvt;}())]();WScript[(function j(" ascii
    $s4  = "n RGb(){return AMd;}()) + b(B) + apq + myBr + (function gX(){return Opkvt;}())]();WScript[Thuh(abMIY) + (function DOZo(){return " ascii
    $s5  = "var bMeSO = \"ct\";var DS = \"bj\\x65\";var uGDY = \"eO\";var Af = \"\\x43\\x72eat\";var Uyl = function KdNO() {return WScript[A" ascii
    $s6  = ";break;}}function tIJt() {return ZMQO && RkD;};if (tIJt()){bSpPm = Uyl[inBZR(Q) + QUBp(jXbcb) + KtqVX + PkMSa(AAPO) + hmjQ(wa) +" ascii
    $s7  = "){return jWzw;}())] < 4 ) {WScript[(function cEr(){return abMIY;}()) + T](YSG() * 10)};yz = false;} catch(e){};}eXPeN = WScript[" ascii
    $s8  = "T;}())](YSG());var Eri = new this[dhA(We) + r(iqWQd) + gjPIA(HBn)]();var lS = Eri[(function ld(){return sOPn;}()) + (function BH" ascii
    $s9  = " K(Gj) + IgcFE(JmGp) + WvC + rFX](mjU(FEsCf) + (function Thlle(){return WHNs;}())) + y(Du) + dmaqs(Nz) + EvwMr(iCwmH) + ollS(jS)" ascii
    $s10 = "r;}()) + (function Nyu(){return Opkvt;}())]();var NCG = \"AxP\";NCG = ntF(lS, WDBB);var dmc = \"ypVgu\";dmc = ntF(gOfa, lS);retu" ascii
    $s11 = "- FfIc;};function U(){return (function zIbC(){return Af;}()) + S(uGDY) + DS + (function pvYt(){return bMeSO;}());};function YSG(" ascii
    $s12 = "){return abMIY;}()) + (function NB(){return T;}())](YSG());var Eri = new this[(function yx(){return We;}()) + pCVAW(iqWQd) + HBn" ascii
    $s13 = "r yz = true; while (yz){try {ZiWn[(function Jhe(){return VYKy;}()) + B0(Ku)]((function afJzM(){return c0;}()), byaV + z0(p0) + U" ascii
    $s14 = " );eXPeN[D0(oe) + (function Y0(){return wKa;}()) + (function u(){return mObP;}())]();Qfxtu(bSpPm);NCG = \"\" + (function ltu(){r" ascii
    $s15 = "m(Ku))]();eXPeN[(function Cyw(){return QbRk;}())] = 1;eXPeN[(function J0(){return Kwohl;}()) + (function V0(){return AnPv;}()) +" ascii
    $s16 = "U()](z1(qf) + (function fAS(){return fbIak;}()) + FqP(cvz) + Acp(nudd) + zIF(nK));eXPeN[((function fkk(){return VYKy;}()) + JmXr" ascii
    $s17 = "TbR) + oTUlF + k(seaKo) + ZMQO ? TWn + I0 + ox + (function Fm(){return wBxhV;}()) : (function Ph(){return rCBX;}()) + ZVbj + (fu" ascii
    $s18 = "(function IWY(){return GO;}()) + OxUeQ(DWVz) + yiwdY(UDfmm) + (function iJ(){return R;}());};function ntF(SIW, FfIc){return SIW " ascii
    $s19 = "){return 22;};function EsHp(){var Eri = new this[(function gqtZ(){return We;}()) + iqWQd + HBn]();var WDBB = Eri[sOPn + (functio" ascii
    $s20 = "F + Umzg, false);ZiWn[gwyz(uk) + RAbYe]();while (ZiWn[dszQ(bUe) + (function ZRGaD(){return f0;}()) + rvg + B1(g1) + (function L(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}