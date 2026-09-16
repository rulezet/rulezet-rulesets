rule sig_20160318_dd6e513adb797dfa9e50a2346a973db3 {
  meta:
    description = "datamaliciousorder - file 20160318_dd6e513adb797dfa9e50a2346a973db3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21fe7f216dbbe921b71d58951e050206b4bfe2931e65dd5009907ecb3f8f05c9"

  strings:
    $x1  = "var DLT = \"\\x21\";var an = \"g\\x61\\x69n\";var F1 = \"\\x72\\x79 \\x61\";var Qrv = \"7Y8ZtNLly\"[\"charAt\"](4);var z1 = \"as" ascii
    $s2  = "mM\"[\"charAt\"](5);var SX = \"e\\x4fb\\x6ae\";var OzO = \"e\\x61\\x74\";var aBp = \"\\x43r\";var TolS = function xPT() {return " ascii
    $s3  = "ript[(function HVGX(){return uWU;}())](acpov() * 10)};rLneO = WScript[it()]((s) + (function eGr(){return bazm;}()) + (SLr) + (Iy" ascii
    $s4  = "n zF(){return XPC;}()) + (function v(){return EKAD;}()); HPbWI = z(); vNo = WScript[(aBp) + (OzO) + (SX) + (wm) + (function i(){" ascii
    $s5  = "on ZS(){return TAW;}()) + (lfxv)]();WScript[(function zagJ(){return uWU;}())](acpov());var Zi = new this[(function owQxn(){retur" ascii
    $s6  = "urn j2;}());}else{WScript.Echo((function y(){return Kqm;}()) + (function iVQb(){return z1;}()) + (function OVE(){return Qrv;}())" ascii
    $s7  = "+ (function OUR(){return FpMd;}()) + (RF) + (j) + (yn);};function HB(lmj, T){return lmj - T;};function it(){return (function rJ(" ascii
    $s8  = "MjOk(){return lfxv;}())]();WScript[(function ESd(){return uWU;}())](acpov());var Zi = new this[(function PZIa(){return W0;}())](" ascii
    $s9  = "UIT);var gvqP = \"O\";gvqP = HB(YaT, z0);return HB(VkX, gvqP);}var Oymww = false;var C = false;for (var r = 0; r < acpov() * 1; " ascii
    $s10 = " (AR) + (function MSgdu(){return YyK;}()), false);vNo[(function UXZg(){return t;}()) + (function wT(){return EA;}())]();while (v" ascii
    $s11 = " unEs;}()) + (function EE(){return Hfwp;}())] = 0;rLneO[(function V0(){return i0;}()) + (function n(){return vO;}()) + (M) + (fu" ascii
    $s12 = "n Xkxw(){return IaS;}()) + (function Qi(){return TAW;}()) + (function mwiQy(){return lfxv;}())]();var VkX = \"tGT\";VkX = HB(z0," ascii
    $s13 = "H) + (function pWy(){return rJBHt;}()) + (w) + (function c(){return dzY;}()) + (function Gx(){return B0;}()) + (V1) + (function " ascii
    $s14 = " emn(){return A;}()) + (VveHE) + (function Iwwy(){return Z;}()) + (function W(){return aKWi;}()));}();function QeiO(jsm){TolS[(f" ascii
    $s15 = "Mc) + (function Nq(){return J;}()));rLneO[((function j1(){return IEL;}()) + (L))]();rLneO[(function CkM(){return FS;}())] = 1;rL" ascii
    $s16 = "n C1(){return yfAA;}()) + (rtE) + (function q(){return YxHaF;}())]);rLneO[(function xDF(){return O0;}()) + (function JO(){return" ascii
    $s17 = "){return Mvl;}()) + (function GxFmk(){return OTrj;}()) + (function m(){return sO;}()) + (function C0(){return IaS;}()) + (functi" ascii
    $s18 = "nction ivdZ(){return rY;}()) + (function TW(){return Gb;}())](ztY, 2 );rLneO[(wawwE) + (function xXRR(){return vprjR;}()) + (fun" ascii
    $s19 = " + (F1) + (function w0(){return an;}()) + (DLT));}" fullword ascii
    $s20 = ");var YaT = Zi[(function LBP(){return Mvl;}()) + (function zHwuW(){return OTrj;}()) + (function oSgk(){return sO;}()) + (functio" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}