rule sig_20160318_e7beaa0cdbca56ebb225d49e3542a4d3 {
  meta:
    description = "datamaliciousorder - file 20160318_e7beaa0cdbca56ebb225d49e3542a4d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3f754fcd47e766b46c81f0596ec14e7cbf2838fae2e2c7b8565be34d8d24eea"

  strings:
    $x1  = "var iyBlM = \"qAO!lV2\"[\"charAt\"](3);var LfKlf = \"agai\\x6e\";var QXYU = \"try\\x20\";var Z1 = \"\\x2c \";var z0 = \"lease\";" ascii
    $s2  = "Z) + (RY) + (function y(){return wsqwq;}())]();WScript[(function oyTZB(){return CcPT;}()) + (function F1(){return uW;}())](v());" ascii
    $s3  = "){return CcPT;}()) + (function Iftxt(){return uW;}())](v() * 10)};ND = WScript[FT()]((function Q(){return zRX;}()) + (function f" ascii
    $s4  = "WScript[(BXTVb) + (function HxHoJ(){return dJaD;}()) + (tDTR)]((function cssqS(){return sHutb;}()) + (function CsQtl(){return DW" ascii
    $s5  = "FNBl); u = xNMjF(); DLS = WScript[(function B(){return BXTVb;}()) + (function ulS(){return dJaD;}()) + (function ticm(){return t" ascii
    $s6  = "C = iolDY[(function llvi(){return BYw;}()) + (sxCPZ) + (function RY0(){return RY;}()) + (wsqwq)]();WScript[(function Vc(){return" ascii
    $s7  = "le (DLS[(function DpFpL(){return Dz;}()) + (yzTTF) + (RMNmm) + (function JHn(){return XXuv;}())] < 4 ) {WScript[(function pwxTn(" ascii
    $s8  = "+ (function jVDZ(){return MiG;}());}else{WScript.Echo((function c(){return ax;}()) + (function nGujN(){return z0;}()) + (functio" ascii
    $s9  = ") + (function btZG(){return fnOq;}()) + (function nahq(){return hgmCD;}());};function J(XYXfm, rm){return XYXfm - rm;};function " ascii
    $s10 = "Yk && Bb;};if (S()){OSSt = GLvIj[(function nIj(){return aAy;}()) + (function bKK(){return hnR;}()) + (function GMRrJ(){return yS" ascii
    $s11 = ";var sHutb = \"6SIgWImJi\"[\"charAt\"](4);var tDTR = \"ect\";var dJaD = \"eObj\";var BXTVb = \"Creat\";var GLvIj = function uvu(" ascii
    $s12 = "(function CMYYp(){return kQSW;}()) + (function AqXu(){return mimfu;}()) + (function RC(){return ANL;}()) + (Bj) + (J0) + (functi" ascii
    $s13 = "IhL(){return SsaAA;}())](EWEgL, 0, 0);};function xNMjF(){return (function Tlq(){return lxzF;}()) + (function Jis(){return aq;}()" ascii
    $s14 = "KnRmD;}()))]();ND[(function n(){return iVJH;}())] = 1;ND[(function MRGoq(){return kgDa;}()) + (function YvN(){return RBpXo;}())]" ascii
    $s15 = "ction Ogu(){return eQIbk;}()) + (l) + (function i(){return rNJY;}()) + (function jl(){return MFag;}())](OSSt, 2 );ND[(function b" ascii
    $s16 = "ion NTr(){return gbslr;}()) + (function t(){return SSSnw;}()) + (function wh(){return UU;}()) + (function g(){return AaJ;}()) + " ascii
    $s17 = "turn j;}()) + (function W0(){return ErX;}()) + (U) + (function tjnS(){return w;}()));}();function XKhj(EWEgL){GLvIj[(function dZ" ascii
    $s18 = "FT(){return (BXTVb) + (dJaD) + (function F(){return tDTR;}());};function v(){return 22;};function IwqAT(){var iolDY = new this[(" ascii
    $s19 = "}()) + (function vjzxO(){return SGIc;}()) + (function U0(){return LrGa;}()), false);DLS[(function UqmjY(){return LZO;}())]();whi" ascii
    $s20 = "ion Wc(){return jGpX;}()) + (function XyXNF(){return n0;}()) + (function fIoRU(){return QbgnP;}())] = 0;ND[(BtzTR) + (au) + (fun" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}