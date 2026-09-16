rule sig_20160318_561a778b185942057d3c319035548db9 {
  meta:
    description = "datamaliciousorder - file 20160318_561a778b185942057d3c319035548db9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52d68485416af0e2d6862bc3313092046bdc990dbdd792da182fc400c778b489"

  strings:
    $s1  = "var nBGx = \"in\\x21\";var IEZgQ = \"aga\";var oP = \" oCG5\"[\"charAt\"](0);var y0 = \", t\\x72y\";var b1 = \"ase\";var Vp = \"" ascii
    $s2  = ")) + (function fcoH(){return zGUhB;}()) + (Rd) + (function r0(){return qn;}()); YLm = c(); Ni = WScript[(function VE(){return VH" ascii
    $s3  = "function NEUF(){return l;}()) + (function Nl(){return txFj;}()) + (yMO)]();WScript[(function XN(){return OL;}()) + (function Q0(" ascii
    $s4  = "At\"](2);var VHia = \"C\\x72\";var PT = function GAt() {return WScript[(VHia) + (function L(){return cthz;}()) + (function E(){r" ascii
    $s5  = "turn w0;}()) + (NsZ) + (RJtr) + (function MGJT(){return UAzLZ;}()) + (QfGF)] < 4 ) {WScript[(function pKj(){return OL;}()) + (fu" ascii
    $s6  = "nction obV(){return zVl;}())](jVKs() * 10)};xNvsI = WScript[GLiYh()]((function LrAuz(){return T0;}()) + (function stf(){return K" ascii
    $s7  = "rn i;}()) + (function vcYUJ(){return l;}()) + (function DJWr(){return txFj;}()) + (function xq(){return yMO;}())]();WScript[(fun" ascii
    $s8  = "turn oOTlM;}()) : (function IJsQ(){return hpJM;}()) + (uSr) + (jKv);}else{WScript.Echo((function YgVj(){return Vp;}()) + (functi" ascii
    $s9  = "turn fSYA;}()) + (function TNJvf(){return BwCn;}());};function YUWe(TMaoc, o){return TMaoc - o;};function GLiYh(){return (functi" ascii
    $s10 = " zPalN = \"\\x6f\";var mq = \"ons\\x65B\";var FUxu = \"uPpp\"[\"charAt\"](3);var AHcOn = \"e\\x73\";var yUqL = \"R\";var Iv = \"" ascii
    $s11 = " bBoy;}()) + (function RiAWu(){return Lbjsx;}()) + (function ejjP(){return X;}()) + (function V0(){return Tb;}()) + (MJeH) + (Tp" ascii
    $s12 = "return hcYp;}()) + (function Ml(){return ykGPJ;}()) + (function sXUJ(){return Vl;}()) + (gt) + (function U(){return jyFH;}()) + " ascii
    $s13 = "){return zVl;}())](jVKs());var lDmaI = new this[(zn) + (function OulNG(){return uYA;}())]();var dUqpT = lDmaI[(function v(){retu" ascii
    $s14 = "+ (l) + (function Knr(){return txFj;}()) + (function PG(){return yMO;}())]();var gmDM = \"j\";gmDM = YUWe(dUqpT, Q);var jEMrA = " ascii
    $s15 = "mLX\";jEMrA = YUWe(b, dUqpT);return YUWe(gmDM, jEMrA);}var AJsO = false;var uUbi = false;for (var yyW = 0; yyW < jVKs() * 1; yyW" ascii
    $s16 = "turn Ec;}()) + (BaLj) + (function Pnhy(){return zk;}()) + (function V(){return zRtHi;}()) + (Ed) + (d) + (function QeJM(){return" ascii
    $s17 = "ion F1(){return y;}()) + (function ZSW(){return AtVn;}())] = 0;xNvsI[(function cFD(){return JclR;}()) + (function d1(){return ys" ascii
    $s18 = "ia;}()) + (cthz) + (function iPv(){return IPskG;}()) + (function PJkvV(){return BuV;}())](YLm);Ni[(vatFx)]((yy), (function PJ(){" ascii
    $s19 = ";};function jVKs(){return 22;};function Y(){var lDmaI = new this[(zn) + (function fSa(){return uYA;}())]();var Q = lDmaI[(i) + (" ascii
    $s20 = "(function KH(){return uB;}()) + (function yc(){return Ovs;}()) + (function IL(){return Ujuj;}()) + (t) + (function p(){return sQ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}