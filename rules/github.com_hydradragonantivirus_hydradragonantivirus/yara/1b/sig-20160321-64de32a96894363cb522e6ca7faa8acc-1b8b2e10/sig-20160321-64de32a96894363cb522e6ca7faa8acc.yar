rule sig_20160321_64de32a96894363cb522e6ca7faa8acc {
  meta:
    description = "datamaliciousorder - file 20160321_64de32a96894363cb522e6ca7faa8acc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "add78c985c267a04e6e3eb3536584c59657a7d3f47c5cb7044477ac273c39420"

  strings:
    $s1  = "function zIM(wubdv){return wubdv;};function JEOpG(tvnr){return tvnr;};var VAaG = \"68\\x3162\";var HcHLP = \"2\\x3183\";function" ascii
    $s2  = " qFsCg = \"ect\";var VZsj = \"t\\x65Obj\";var PMaX = \"Cre\\x61\";var QCEgE = function rDRR() {return WScript[RFQ(PMaX) + (funct" ascii
    $s3  = "V) + R; wvKs = U0(); x = WScript[D(PMaX) + (function Zo(){return VZsj;}()) + (function Zg(){return qFsCg;}())](wvKs); var nchcs " ascii
    $s4  = ";var FpjT = g[(function gVVVe(){return TkvWn;}()) + nB(a) + f + (function H0(){return tl;}()) + y(vWq)]();WScript[y0(kacw) + E0(" ascii
    $s5  = "n agRLV(){return vWq;}())]();WScript[B(kacw) + SBj(wfY)](fqSuX());var g = new this[brQX(LY) + (function NyRb(){return mX;}())]()" ascii
    $s6  = ";}Dojp = WScript[yDX()](gPea + Ygjp(a0) + Aeh(VRj) + ngfs + nRdu);Dojp[((function C(){return fnMYB;}()) + (function z(){return N" ascii
    $s7  = "return N - bSPMa;};function yDX(){return pBdf(PMaX) + N0(VZsj) + (function XYO(){return qFsCg;}());};function fqSuX(){return 22;" ascii
    $s8  = "\\x41\\x74\"](5);var h = \"sen\";var kRY = \"p\\x6f\";var wIfHt = \"\\x2fa\";var JF = \"p:\\x2f\";var MTAl = \"htt\";function fh" ascii
    $s9  = "o0;}()) + uzp(VI) + (function whhG(){return w1;}())] < 4 ) {WScript[yhAGa(kacw) + wfY](fqSuX() * 10)};nchcs = false;} catch(e){}" ascii
    $s10 = ") + fga(lv) + (function XNc(){return JNT;}()) + e + (function aBQVK(){return Ully;}())]((function tN(){return V;}()) + EVmL + X(" ascii
    $s11 = " + KWecd](x[nFAMX + dnMO(s0) + s1(nXRWE) + (function IVuyt(){return ekNd;}()) + HFj(D2)]);Dojp[(function PJVp(){return TR;}()) +" ascii
    $s12 = "nction m0(){return XmV;}()) + (function dXtwG(){return yL;}()) + (function IjM(){return qJRT;}()) + X0(HTG) + (function mtL(){re" ascii
    $s13 = " = \"sW\";L = pK(MIjyb, FpjT);return pK(jJUHq, L);}var loTzx = false;var wEo = false;for (var Hl = 0; Hl < fqSuX() * 1; Hl++){if" ascii
    $s14 = "()) + (function EVL(){return s;}()) + (function K0(){return kT;}()) + AAVN(eWV) + eNiW(DOfc) + cktj(Qg);};function pK(N, bSPMa){" ascii
    $s15 = "JYI, false);x[GlZ(EZvFL) + (function sV(){return w0;}())]();while (x[(function jTBU(){return WZCdL;}()) + (function O1(){return " ascii
    $s16 = "jnU;}()) + rnnoO(LBc) + (function hpw(){return Ljstj;}()) + (function HYrW(){return ggFX;}()) + (function WxSyU(){return kBI;}()" ascii
    $s17 = "wfY)](fqSuX());var g = new this[(function arKcn(){return LY;}()) + l(mX)]();var MIjyb = g[(function hcp(){return TkvWn;}()) + Kz" ascii
    $s18 = "Cz)) + (function S0(){return BYccZ;}()) + mIh(Y) + (function cFU(){return CI;}()) + D1 + (function pWK(){return Ie;}()) + EErI(b" ascii
    $s19 = "};function U(){var g = new this[H(LY) + (function CbT(){return mX;}())]();var tpIGt = g[TkvWn + uY(a) + K1(f) + q(tl) + (functio" ascii
    $s20 = "n(){return VZsj;}()) + qFsCg](fRKJ + c(I) + (function NL(){return jV;}()) + pHfP + cPgG + (function D0(){return r;}()) + llNK);}" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}