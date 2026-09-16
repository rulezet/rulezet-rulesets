rule sig_20160321_731e5de5d4fcdff0fe915232955b51d7 {
  meta:
    description = "datamaliciousorder - file 20160321_731e5de5d4fcdff0fe915232955b51d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de5b13745c864b8cb5fdfb513134358bdbb589e351208854115ee2a24b22c3c2"

  strings:
    $s1  = "function ogFe(AYm){return AYm;};function MH(XYn){return XYn;};function D(HXkoW){return HXkoW;};var RUGAi = \"Y20ZKdw\";var YFWd " ascii
    $s2  = "}())]();WScript[(function bgq(){return r1;}()) + ZqrX](oCu());var MSl = new this[(function q0(){return KP;}())]();var lboZa = MS" ascii
    $s3  = ")) + n0; YS = x(); q = WScript[NA + (function b(){return C;}()) + (function Ge(){return zS;}()) + FimSv](YS); var GxZIN = true; " ascii
    $s4  = "f = WScript[ZcVQO()](yXkUb(n1) + Yak + Alz + (function g(){return S0;}()) + G1(hR));qCf[(YUz(posbP) + (function l1(){return XD;}" ascii
    $s5  = "l[rI + (function EfKL(){return aKN;}()) + MaiK + Bm(GcX) + (function A(){return G0;}())]();WScript[r1 + ZqrX](oCu());var MSl = n" ascii
    $s6  = "\"eateO\";var NA = \"\\x43r\";var JPwSP = function uZ() {return WScript[G(NA) + (function ZaGFa(){return C;}()) + RDEXp(zS) + (f" ascii
    $s7  = "l) + (function WTkc(){return jS;}());};function lxAQ(hNREz, rVnme){return hNREz - rVnme;};function ZcVQO(){return YaN(NA) + C + " ascii
    $s8  = "{return S && zBf;};if (Zv()){SLa = JPwSP[jj + KBE(SvT) + (function z(){return SNttB;}()) + YC + rjT + b0(Lz) + m0 + (function Q(" ascii
    $s9  = " < 4 ) {WScript[(function qOiY(){return r1;}()) + (function dmOd(){return ZqrX;}())](oCu() * 10)};GxZIN = false;} catch(e){};}qC" ascii
    $s10 = "n = \"/\";var bba = \"\\x68ttp:\";function h(HwM){return HwM;};var j = \"G\\x45T\";function jNA(FA){return FA;};function YUz(UFY" ascii
    $s11 = "var foVra = \"\\x65p\";var c = iaKC[\"charAt\"](0);var f = \"Sl\";function pTDS(Om){return Om;};var v = \"ate\";var SPoA = \"ad" ascii
    $s12 = "\"16\\x32\";var Tq = \"68\";var ch = \"3\";var uVQ = \"18\";var UPa = RUGAi[\"charAt\"](1);function Rke(fr){return fr;};var T = " ascii
    $s13 = "= \"eU\";var CD = UbYFr[\"charAt\"](0);var yPhk = \"c\\x6cos\";function vMA(kI){return kI;};function px(M3){return M3;};var R = " ascii
    $s14 = "ion CBd(sbq){return sbq;};var cPYQ = \"iXJl1b1B\";var tuZ = \"l\";var qCMt = tuZ[\"charAt\"](0);var wu = cPYQ[\"charAt\"](3);var" ascii
    $s15 = " a = \"\\x72e\";function ovdp(d){return d;};var MXr = \"voMmnLEQe9\";var zODd = \"d\";var nA = MXr[\"charAt\"](4);var sCO = \"s" ascii
    $s16 = " iVNt = \"R\\x65s\\x70\";function lv(fHbeb){return fHbeb;};var M0 = \"DearO\";var nE = M0[\"charAt\"](1);var aYjPs = \"w\\x72it" ascii
    $s17 = "dxhn(cOL){return cOL;};var I0 = \"fMQ4jb\";var Nsdh = \"gyfi1lPG\";var PfBqm = Nsdh[\"charAt\"](2);var hC = \"\\x73\\x64\";var p" ascii
    $s18 = "q = \"T\\x45\";var hwost = l0[\"charAt\"](5);function KBE(I){return I;};function b0(RawAA){return RawAA;};var BRz = \"gs\";var w" ascii
    $s19 = "r ev = T[\"charAt\"](1);var wuIRx = \"d\";var wRd = \"f\\x61\\x73\";var bEVHY = \"a\\x73d\";function t(CJi){return CJi;};functio" ascii
    $s20 = ";var eN = \"Date\";var PZMC = \"GflXpVYQz\";var ZqrX = PZMC[\"charAt\"](4);var r1 = \"Sle\\x65\";function e(WwwbN){return WwwbN;" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}