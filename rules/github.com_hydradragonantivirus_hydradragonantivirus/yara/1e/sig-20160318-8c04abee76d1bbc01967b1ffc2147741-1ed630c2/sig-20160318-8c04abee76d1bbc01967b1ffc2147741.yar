rule sig_20160318_8c04abee76d1bbc01967b1ffc2147741 {
  meta:
    description = "datamaliciousorder - file 20160318_8c04abee76d1bbc01967b1ffc2147741.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d30d09a8fa0d5d6f192f98e89b4ab9f15446a97f6483ff72baff775a583e734a"

  strings:
    $s1  = "var VWg = \"i\\x6e\\x21\";var WI = \" \\x61g\\x61\";var PKAH = \"\\x74ry\";var fZJM = \"\\x73e, \";var Pye = \"le\\x61\";var AF " ascii
    $s2  = "(RcDW) + (function KwF(){return wThyI;}()) + (function Z(){return sr;}())]();WScript[(Ono)](Pbwq());var gIX = new this[(function" ascii
    $s3  = " p;}()) + (function c(){return te;}()) + (DiFK)] < 4 ) {WScript[(Ono)](Pbwq() * 10)};buDhQ = WScript[eqrs()]((function N0(){retu" ascii
    $s4  = "ion UwljS(){return RcDW;}()) + (function tE(){return wThyI;}()) + (function aIWLb(){return sr;}())]();WScript[(function La(){ret" ascii
    $s5  = " kjWa = ZFFp(); gv = WScript[(function GMia(){return YiPl;}()) + (function AfT(){return Us;}()) + (function uctgI(){return WRN;}" ascii
    $s6  = "urn r;}());}else{WScript.Echo((AF) + (function V0(){return Pye;}()) + (function h(){return fZJM;}()) + (function DR(){return PKA" ascii
    $s7  = "(){return Ki;}());};function FO(myer, rxxUn){return myer - rxxUn;};function eqrs(){return (function ykpFH(){return YiPl;}()) + (" ascii
    $s8  = "f (DOM() != 0){Jsphx = true;jq = true;break;}}function xO() {return Jsphx && jq;};if (xO()){Ei = gg[(B0) + (function kXVcc(){ret" ascii
    $s9  = " = \"JUtaPZMv\"[\"charAt\"](2);var g = \"e\\x63\";var WRN = \"eO\\x62j\";var Us = \"eat\";var YiPl = \"Cr\";var gg = function Q(" ascii
    $s10 = "MQd(){return wxeF;}()) + (function Xvq(){return qhx;}()) + (gUWv), false);gv[(function IDH(){return WiKHN;}()) + (function DRccC" ascii
    $s11 = "turn UAy;}()) + (function qKQ(){return De;}()) + (OLt) + (function hvxda(){return c0;}()) + (function fUfb(){return k;}()) + (fu" ascii
    $s12 = "eturn IMmi;}()) + (function QUrk(){return bkTm;}()) + (function C(){return Hvz;}()) + (function xMG(){return QtEnS;}()) + (funct" ascii
    $s13 = "zfQ(){return VEbdk;}()) + (function vdQx(){return Fea;}())]((function fLDv(){return HkFub;}()) + (function mtC(){return WyuL;}()" ascii
    $s14 = " Y(){return fYYPj;}()) + (function tO(){return JKWLN;}())]();var hOrf = gIX[(function VzaK(){return ktLmD;}()) + (function Qlj()" ascii
    $s15 = "rn X;}()) + (function gr(){return Yu0;}()) + (function Japc(){return lp;}()) + (function kB(){return uO;}()));buDhQ[((function F" ascii
    $s16 = "nction ku(){return LSehy;}()) + (function fUD(){return TxNhU;}()) + (function zB(){return bWBe;}()) + (function GFuRH(){return s" ascii
    $s17 = "u\";Zm = FO(hOrf, jvFP);return FO(RLZpu, Zm);}var Jsphx = false;var jq = false;for (var BroGg = 0; BroGg < Pbwq() * 1; BroGg++){" ascii
    $s18 = ")) + (uy) + (function bOEYw(){return oBG;}()) + (function ZqMzK(){return Mlpg;}()) + (function htL(){return ZoTn;}()) + (jWUtQ);" ascii
    $s19 = "(){return ZsKJs;}()) + (function wG(){return eMyob;}())]();while (gv[(function kPcXW(){return OEoFt;}()) + (function OM(){return" ascii
    $s20 = "{return IMmi;}()) + (function y(){return bkTm;}()) + (function xNs(){return Hvz;}()) + (function KQO(){return QtEnS;}()) + (func" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}