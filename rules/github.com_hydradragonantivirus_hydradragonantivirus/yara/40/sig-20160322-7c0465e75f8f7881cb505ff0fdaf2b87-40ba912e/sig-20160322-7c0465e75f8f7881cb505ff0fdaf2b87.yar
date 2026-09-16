rule sig_20160322_7c0465e75f8f7881cb505ff0fdaf2b87 {
  meta:
    description = "datamaliciousorder - file 20160322_7c0465e75f8f7881cb505ff0fdaf2b87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbf9d0b59ce3d482c0f4ffe53f7404d5ed2261762827109ef82936e3ed25b5f2"

  strings:
    $s1  = "function PRh(myQZc){return myQZc;};function oiUvK(w){return w;};function IG(u){return u;};var Qfrk = \"\\x316\\x32\";var Uwp = " ascii
    $s2  = "x65\\x63t\";var JLL = \"\\x65Ob\";var DdBUS = \"Creat\";var OKQj = function k() {return WScript[ukzrP(DdBUS) + JLL + ai(AIVX)](b" ascii
    $s3  = "C[hIYoc + CW(qBy) + (function ETe(){return TA;}()) + Bloo + gE + (function vXC(){return h;}()) + Xcty]();WScript[(function FvRI(" ascii
    $s4  = "K) + (function SzW(){return fZipi;}()) + C0(Di) + Z0 + lXxKb(cxZs); MpTN = ZmBR(); Yz = WScript[DdBUS + (function zsim(){return " ascii
    $s5  = "nction akhg(){return bFPQ;}()) + xu(Dgpqt)] < 4 ) {WScript[OzGmH(T) + (function FL(){return TqH;}()) + (function Bm(){return s;}" ascii
    $s6  = " + Xcty]();WScript[(function dG(){return T;}()) + TqH + jKBLZ(s)](qnJA());var MQC = new this[zN(sr) + FCiZy(i0)]();var AHjj = MQ" ascii
    $s7  = ";};function a(ZeDG, Jn){return ZeDG - Jn;};function YJSMQ(){return AP(DdBUS) + (function ZG(){return JLL;}()) + AIVX;};function " ascii
    $s8  = " = 0; kmRBa < qnJA() * 1; kmRBa++){if (m() != 0){os = true;Y = true;break;}}function uF() {return os && Y;};if (uF()){KFcuS = OK" ascii
    $s9  = "())](qnJA() * 10)};ijJ = false;} catch(e){};}n = WScript[YJSMQ()](QhAm(kUk) + piOJu(A0) + (function SBVHJ(){return zpzBA;}()) + " ascii
    $s10 = "unction Etlt(){return TA;}()) + (function AXWd(){return Bloo;}()) + (function VGs(){return gE;}()) + (function X(){return h;}())" ascii
    $s11 = "e) + os ? (function dd(){return vFd;}()) + msl + (function ctqfM(){return rb;}()) : PRh(nQvP) + oiUvK(zM) + IG(Uwp) + (function " ascii
    $s12 = "jg;}()) + (function lmxaN(){return QwLNJ;}()) + d + Lvsb(clJT) + IJU(mYy) + (function hk(){return OA;}()) + bfr(BDH) + raLhz(XeN" ascii
    $s13 = "A) + (function cbtBN(){return TPk;}()) + xU(XPMOY) + v + Tp0 + (function fUA(){return HfpM;}()) + uGhLq + VgL(xLiZA), false);Yz[" ascii
    $s14 = "JQd = \"\" + (function CmTA(){return ZY;}()) + (function K0(){return EClQ;}()) + Ewbas + E0(AC) + aUh + (function mGWik(){return" ascii
    $s15 = ";function Q(A){OKQj[YAHoc(we)](A, 0, 0);};function ZmBR(){return OGr(Hdu) + (function lo(){return uoz;}()) + WxG + DT + Squo(PY)" ascii
    $s16 = "P(Ynh) + (function hkh(){return Mkad;}()) + (function ctz(){return DB;}()) + (function YEiPN(){return eDDL;}()) + LHCYw(pExrM)])" ascii
    $s17 = "+ (function YewK(){return jI;}()) + (function Ow(){return RbgT;}()) + F(U0) + LEHX(esHLL)](KFcuS, 2 );n[HYoR(sIM)]();Q(KFcuS);fx" ascii
    $s18 = "(function vt(){return Lxb;}()) + Q0]();while (Yz[NzL + (function xEiO(){return mV;}()) + (function SqOYu(){return PKf;}()) + (fu" ascii
    $s19 = "JLL;}()) + AIVX](MpTN); var ijJ = true; while (ijJ){try {Yz[(function tRhjV(){return IZ;}())]((function MO(){return P0;}()), RfP" ascii
    $s20 = "){return JUNi;}()) + (function NRFh(){return CM;}())]((function LlOXL(){return zJAu;}()) + MAaiW(dNnr)) + onpD(MKvf) + Pkdvh(drs" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}