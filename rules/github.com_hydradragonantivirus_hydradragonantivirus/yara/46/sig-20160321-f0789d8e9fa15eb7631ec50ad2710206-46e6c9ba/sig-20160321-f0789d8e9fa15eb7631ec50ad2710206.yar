rule sig_20160321_f0789d8e9fa15eb7631ec50ad2710206 {
  meta:
    description = "datamaliciousorder - file 20160321_f0789d8e9fa15eb7631ec50ad2710206.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f907c5224a54dc2f2fe9249fea0ffe1bc1b5b3167f0c11903e1864e1612eafe6"

  strings:
    $s1  = "function D0(LLtWT){return LLtWT;};var k0 = \"\\x31\\x362\";var k = \"368\";var XGa = \"21\\x38\";function vryp(EH){return EH;};v" ascii
    $s2  = ") + BqiW(XW) + iALiF + wCxT(v) + MSbDo(HsjTS)]();WScript[Au(K)](LdDK());var McrFV = new this[lw(Wm) + (function WGjvX(){return x" ascii
    $s3  = " PMTio() {return WScript[Dn(donpC) + (function fdy(){return KIBe;}()) + tu + pJIMK(VA)](T(I0) + oNiV + TOGG(QWH) + h(aNQPS));}()" ascii
    $s4  = "+ (function FT(){return Xd;}()); BAo = nMHXo(); oJc = WScript[donpC + nFlr(KIBe) + IuNKx(tu) + VA](BAo); var mWosH = true; while" ascii
    $s5  = ")) + (function ovX(){return v;}()) + (function dEc(){return HsjTS;}())]();WScript[(function difh(){return K;}())](LdDK());var Mc" ascii
    $s6  = "unction eENLL(){return eHbM;}()) + (function xGQ(){return kz;}()) + s1(iP) + p0] < 4 ) {WScript[kPTBw(K)](LdDK() * 10)};mWosH = " ascii
    $s7  = "4s\";var U = \"\\x73\\x65co\";var s = \"lli\";var aa = sT[\"ch\\x61rAt\"](3);var fCriA = \"getM\";var Hd = \"te\";var oDrQS = \"" ascii
    $s8  = "return gsSci;}()) + X(BV) + i(a) + A(hG) + TadW;};function FL(LoVLk, fVKgc){return LoVLk - fVKgc;};function MprO(){return SeSx(d" ascii
    $s9  = " * 1; nJc++){if (R() != 0){uZSy = true;FIH = true;break;}}function Yn() {return uZSy && FIH;};if (Yn()){vwXJ = MXVEB[m(hQQ) + OV" ascii
    $s10 = "false;} catch(e){};}SByX = WScript[MprO()]((function gd(){return dWzE;}()) + (function GNPa(){return MFd;}()) + RhR(w));SByX[(LK" ascii
    $s11 = "return xEEgt;};var AJSrp = \"oboEQ\";var HsjTS = \"n\\x64s\";var v = AJSrp[\"ch\\x61rAt\"](2);var iALiF = \"c\";var XW = \"l\\x6" ascii
    $s12 = "r MJ = \"c\\x74\";var jU = o[\"ch\\x61rAt\"](2);var ktuO = \"j\";var roix = \"eOb\";var do0 = \"reat\";var sc = \"C\";function M" ascii
    $s13 = "C = \"\\x74t\";var Gnck = MeYx[\"ch\\x61rAt\"](1);function UhY(sj){return sj;};function ONQIw(LtWe){return LtWe;};var KtD = \"ST" ascii
    $s14 = "r ZsMTZ = KtD[\"ch\\x61rAt\"](1);var HN = \"G\\x45\";function B(Qjs){return Qjs;};var s0 = \"en\";var LKgdY = \"op\";var o = \"A" ascii
    $s15 = "6\";var mc = \"Bs\\x65n\";function YS(dLL){return dLL;};var P = \"%/\";var OM = \"\\x25\\x54EM\\x50\";function m(j0){return j0;}" ascii
    $s16 = "ar eOk = \"inHN\";var qA = eOk[\"ch\\x61rAt\"](1);var dx = \"\\x69o\";var rA = \"t\";var mLJoo = \"posi\";function nhTI(s2){retu" ascii
    $s17 = "var dPB = \"getMi\";function Lfbi(ZQCn){return ZQCn;};function wur(oO){return oO;};function lw(pqdfY){return pqdfY;};var L = \"4" ascii
    $s18 = " u = \"\\x4d\";var eHXhg = \"EnhoN\";var JAIY = eHXhg[\"ch\\x61rAt\"](1);var Fd = \"R\\x75\";function T(ZHk){return ZHk;};functi" ascii
    $s19 = "return GVEds;}()) + qkH(rBMNc) + (function LxOCN(){return Xu;}()) + FBFs(XAcWM) + rx(gRfM) + uZSy ? vryp(oHlA) + (function cFy()" ascii
    $s20 = "{return LiOT;}()) : D0(XGa) + k + k0;}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}