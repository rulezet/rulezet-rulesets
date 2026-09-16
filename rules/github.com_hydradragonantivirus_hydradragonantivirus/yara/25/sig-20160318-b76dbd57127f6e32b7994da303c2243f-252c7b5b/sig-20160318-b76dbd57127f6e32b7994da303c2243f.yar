rule sig_20160318_b76dbd57127f6e32b7994da303c2243f {
  meta:
    description = "datamaliciousorder - file 20160318_b76dbd57127f6e32b7994da303c2243f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ab0a7300ce92605df7b6b8c172b593b0074e04f1e368e64bf42631bdd1e65ea"

  strings:
    $s1  = "var Rpn = \"n!\";var Hq = \"\\x69\";var ac = \"a\";var st = \"g\";var PtcgR = \"Eja6n\"[\"charAt\"](2);var GhU = \"ry \";var s =" ascii
    $s2  = "ction Y() {return WScript[(Nl) + (hgACz) + (function RXdK(){return GQ;}()) + (function xy(){return nS;}())]((function N(){return" ascii
    $s3  = "eturn jv;}()) + (function XIgW(){return k;}())]();WScript[(function QISr(){return mZfra;}()) + (function X(){return xgJBY;}())](" ascii
    $s4  = "(function WLJC(){return xl;}()) + (function HSxX(){return jv;}()) + (function q(){return k;}())]();WScript[(function bL(){return" ascii
    $s5  = "{return qR;}())] < 4 ) {WScript[(function QehKR(){return mZfra;}()) + (function xP(){return xgJBY;}())](f() * 10)};hh = WScript[" ascii
    $s6  = " YqO(){return x;}()) + (function w(){return nz;}());}else{WScript.Echo((function gEi(){return GJSrD;}()) + (function q1(){return" ascii
    $s7  = "rn Xbgrt - SQaTk;};function vHoU(){return (function jIt(){return Nl;}()) + (function Fc(){return hgACz;}()) + (function rE(){ret" ascii
    $s8  = "urn PMAy && EAhfc;};if (UL()){jA = ORFq[(function JH(){return Qu;}()) + (zkQF) + (PfRS) + (function HuK(){return l0;}()) + (func" ascii
    $s9  = ") + (function Vw(){return fMjKo;}()) + (fKxV), false);EIcb[(function C0(){return Gwscs;}()) + (function EhpZ(){return y;}())]();" ascii
    $s10 = "f());var wR = new this[(function Vva(){return LfhSO;}())]();var eWu = wR[(llUWH) + (function GcvE(){return WaKc;}()) + (NykM) + " ascii
    $s11 = "())] = 1;hh[(function a0(){return UCwMS;}()) + (function gYk(){return RT;}())](EIcb[(N0) + (function cZYE(){return JoBGh;}()) + " ascii
    $s12 = ") + (xi)]((function ssaa(){return UJxk;}()) + (function mh(){return WjBE;}()), (function RJh(){return oM;}()) + (function pTmB()" ascii
    $s13 = " a;}()) + (function qjm(){return wZl;}()) + (uIfZN) + (function pzW(){return fDOC;}()));}();function Tp(DWGlA){ORFq[(function na" ascii
    $s14 = "utkv;}()) + (function zSv(){return lmd;}())](jA, 2 );hh[(function nLCD(){return MvvkW;}()) + (function mWVf(){return vcb;}())]()" ascii
    $s15 = "eturn Ogci;}()) + (function Vs(){return CqzYz;}()) + (function dTXNP(){return elD;}()) + (nzXjM) : (vfpaS) + (eVyhC) + (function" ascii
    $s16 = "n Vwvmv;}()));hh[((function qb(){return sQhgQ;}()) + (function iEWI(){return xi;}()))]();hh[(G) + (function HVoWE(){return ayf;}" ascii
    $s17 = "(function vdOHI(){return B1;}()) + (VbSSS)]);hh[(dPuUW) + (function Z(){return BAL;}()) + (V) + (RBaaX) + (sHH)] = 0;hh[(functio" ascii
    $s18 = " BlI;}()) + (function fPCkt(){return fPmX;}()) + (function pT0(){return s;}()) + (function Mh(){return GhU;}()) + (PtcgR) + (fun" ascii
    $s19 = "urn GQ;}()) + (nS);};function f(){return 22;};function jb(){var wR = new this[(function tkg(){return LfhSO;}())]();var EVw = wR[" ascii
    $s20 = "ction qHZq(){return llUWH;}()) + (WaKc) + (function GSpt(){return NykM;}()) + (function PZx(){return xl;}()) + (function XZI(){r" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}