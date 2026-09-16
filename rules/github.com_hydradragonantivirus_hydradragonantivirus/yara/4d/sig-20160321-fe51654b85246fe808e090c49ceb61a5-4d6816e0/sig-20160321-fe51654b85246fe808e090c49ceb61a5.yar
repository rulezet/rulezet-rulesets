rule sig_20160321_fe51654b85246fe808e090c49ceb61a5 {
  meta:
    description = "datamaliciousorder - file 20160321_fe51654b85246fe808e090c49ceb61a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12539d1662b4b9945c826b802a574de588480539de7226f9f229e9366767fd35"

  strings:
    $x1  = "function E(RLDRK){return RLDRK;};function c0(OdWgM){return OdWgM;};var aRlUZ = \"2\";var qj = aRlUZ[\"\\x63\\x68arAt\"](0);var s" ascii
    $s2  = "\"\\x63\\x68arAt\"](0);var Di = \"PQ4\";var Wfi = \"\\x37ETpr\";var ACgoS = \"%\\x2f\";var oYd = \"%TEMP\";function jxTA(nTESd){" ascii
    $s3  = "}()) + dE + (function I(){return OCO;}()) + SQr(OcHzy)]();WScript[PjssC(H) + z0](PL());var wYAeh = new this[(function Fqss(){ret" ascii
    $s4  = "urn JUv;}())]();var mMVl = wYAeh[aVuz(KRyZW) + s(dE) + (function gcKsg(){return OCO;}()) + OcHzy]();WScript[H + (function pc(){r" ascii
    $s5  = "74eObj\";var yy = \"Crea\";var anm = function ZnQk() {return WScript[jyhjX(yy) + (function clBFP(){return zu;}()) + (function qD" ascii
    $s6  = "\\x68arAt\"](4);function ufOVc(W){return W;};var StZm = \"Run\";function UAz(bxsG){return bxsG;};function nOMG(e){return e;};var" ascii
    $s7  = "n Sf(){return yxpA;}()) + dpvpQ(VjUk) + Ov(W0);};function HNwQ(FZ, AIBl){return FZ - AIBl;};function WsrB(){return HlG(yy) + vyl" ascii
    $s8  = "return K;}())]((function gcsr(){return MbIn;}()) + UAz(Nk) + nOMG(OzF) + jeT);}();function qDJKh(rtHl){anm[ufOVc(StZm)](rtHl, 0," ascii
    $s9  = "F(aqhz) + (function lks(){return mAYbc;}())] < 4 ) {WScript[EvbjO(H) + uHlc(z0)](PL() * 10)};cFNQ = false;} catch(e){};}Mr = WSc" ascii
    $s10 = "x70\";var zF = \"\\x68\\x74\";var Ugm = \"GET\";function Witu(bxS){return bxS;};function yeO(pYcDj){return pYcDj;};var i0 = \"88" ascii
    $s11 = "SfEor\";var v1 = \"\\x73e\";var MFx = pp[\"\\x63\\x68arAt\"](5);var C0 = \"c\\x6c\";function uViMs(P1){return P1;};function EkbU" ascii
    $s12 = "function E(RLDRK){return RLDRK;};function c0(OdWgM){return OdWgM;};var aRlUZ = \"2\";var qj = aRlUZ[\"\\x63\\x68arAt\"](0);var s" ascii
    $s13 = "= \"\\x61te\";var aqhz = \"st\";var bjV = B0[\"\\x63\\x68arAt\"](5);var R0 = \"ea\\x64\";var HTqc = QfQhG[\"\\x63\\x68arAt\"](0)" ascii
    $s14 = "F[\"\\x63\\x68arAt\"](2);var S = \"o\";function AlpZ(SXggD){return SXggD;};function ybi(NNyp){return NNyp;};function X(QWSu){ret" ascii
    $s15 = "\";var DnMr = \"kjaos\";var M = \"lf\";var nW = ZfqS[\"\\x63\\x68arAt\"](4);var gLQB = \"\\x61s\";function xGfi(T0){return T0;};" ascii
    $s16 = "on s(s0){return s0;};var OcHzy = \"d\\x73\";var OCO = \"con\";var dE = \"llise\";var KRyZW = \"getMi\";var JUv = \"\\x44ate\";va" ascii
    $s17 = "AeQ(){return nW;}()) + (function mm(){return M;}()) + DnMr + YL(Fj) + (function Ww(){return z2;}()) + Gm(RO) + ke + f(PPNq) + Da" ascii
    $s18 = "+ UVOQm(v0) + dkHz(vp) + (function qYXhq(){return OH;}())]);Mr[(function jh(){return wayjq;}()) + FMVW(AHLM) + Gq(LDL)] = 0;Mr[u" ascii
    $s19 = " KHwkd;}()) + Witu(qoajq)]((function z1(){return Ugm;}()), (function AqO(){return zF;}()) + (function KLcii(){return a;}()) + YZ" ascii
    $s20 = "H(wCX) + (function TNBBa(){return Q0;}()) + Vkm ? NS(HfNEa) + DDNGI + (function fHv(){return PZba;}()) : E(GWoJ) + c0(sRw) + qj;" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}