rule sig_20160318_1c8c7134745ce9c1069cfa616b43c788 {
  meta:
    description = "datamaliciousorder - file 20160318_1c8c7134745ce9c1069cfa616b43c788.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cea2eeb652acde6e7a0367aee9a6a94fee64b7881533c050b443c4d4b82041f9"

  strings:
    $s1  = "var nJRm = \"h!GxiFA\"[\"charAt\"](1);var xb0 = \"i\\x6e\";var b2 = \"\\x61\\x67a\";var BF = \"\\x74r\\x79 \";var Toig = \"\\x2c" ascii
    $s2  = ";}())](uaKt() * 10)};SZ = WScript[FFJd()]((xUPn) + (function L0(){return Ax;}()) + (function sIOtT(){return rytWa;}()) + (functi" ascii
    $s3  = " rCZi(){return wLGR;}()) + (function c(){return da;}()); qAuS = AB(); InNKE = WScript[(function Dilm(){return OhwbS;}()) + (func" ascii
    $s4  = "IJP;}()) + (xT) + (function IwHu(){return KxNI;}())] < 4 ) {WScript[(function irqh(){return h;}()) + (function hl(){return ulQGo" ascii
    $s5  = "n x3;}());}else{WScript.Echo((function ZvSh(){return g;}()) + (function Y(){return YuKJ;}()) + (function VGg(){return ER;}()) + " ascii
    $s6  = ")) + (function N(){return rn;}()) + (function Yfa(){return CBBWK;}()) + (zFY)]();WScript[(function kR(){return h;}()) + (ulQGo)]" ascii
    $s7  = "(){return zFY;}())]();WScript[(function HJr(){return h;}()) + (ulQGo)](uaKt());var jH = new this[(function kfG(){return chFy;}()" ascii
    $s8  = " + (function uOOlH(){return jsa;}()) + (function hmM(){return Mlv;}());};function x(T, K){return T - K;};function FFJd(){return " ascii
    $s9  = "urn Akc;}()) + (function cJLT(){return vjHoz;}()) + (function IlT(){return t;}()) + (function yBInH(){return QT;}()) + (function" ascii
    $s10 = " E++){if (DkLhz() != 0){O = true;Et = true;break;}}function b() {return O && Et;};if (b()){Zsyfk = C[(yuLJZ) + (function j(){ret" ascii
    $s11 = " gF(){return DngPN;}()), (function K0(){return al;}()) + (function pZDf(){return KGbeQ;}()) + (v) + (function jvaKI(){return SgC" ascii
    $s12 = "n;}()) + (function B0(){return lJ;}()) + (function gQ(){return FBE;}()) + (function Bk(){return y1;}()) + (pXRv) + (function V1(" ascii
    $s13 = "nction kO(){return Rj;}()) + O ? (function ZKLe(){return w0;}()) + (function EJXh(){return I1;}()) + (function b1(){return ZA;}(" ascii
    $s14 = "urn iZU;}()) + (b0) + (function slvBE(){return i;}()) + (function Men(){return kwR;}()) + (pj) + (function RRZ(){return Lk;}()) " ascii
    $s15 = "]();SZ[(PQFR) + (function gcx(){return q;}()) + (function l0(){return IPPf;}())] = 1;SZ[(function RYMKa(){return CWY;}())](InNKE" ascii
    $s16 = ")) : (function nd(){return VBL;}()) + (function CvCi(){return cFv;}()) + (function aKcd(){return lY;}()) + (function JIo(){retur" ascii
    $s17 = "(function ACX(){return bAGv;}()) + (function qzq(){return rn;}()) + (function y0(){return CBBWK;}()) + (zFY)]();var xb = \"zFTY" ascii
    $s18 = "ZcVD(){return NCJ;}()) + (Vkae) + (function yww(){return qa;}()) + (function DuMcE(){return rjzhL;}()) + (function cYEc(){return" ascii
    $s19 = "on yfjXY(){return j0;}()) + (function uE(){return DG;}()));SZ[((function A(){return xu;}()) + (function vwnc(){return jivD;}()))" ascii
    $s20 = " Ic;}())]((function snfo(){return kP;}()) + (RO) + (function H(){return qMHr;}()) + (function e0(){return IU;}()) + (function ln" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}