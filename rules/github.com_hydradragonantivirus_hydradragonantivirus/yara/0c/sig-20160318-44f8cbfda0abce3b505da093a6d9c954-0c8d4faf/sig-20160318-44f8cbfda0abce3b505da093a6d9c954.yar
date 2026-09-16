rule sig_20160318_44f8cbfda0abce3b505da093a6d9c954 {
  meta:
    description = "datamaliciousorder - file 20160318_44f8cbfda0abce3b505da093a6d9c954.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79c4e8291fea5c28c8710469cd5a7a1c79eb4bf4b7e5792b24c53e3e0da0fd54"

  strings:
    $s1  = "var Us = \"i\\x6e!\";var Q = \"ag\\x61\";var uyaA = \"a Q\"[\"charAt\"](1);var J = \"\\x20tr\\x79\";var vDgU = \"\\x65\\x2c\";va" ascii
    $s2  = " = \"Creat\";var Aac = function frt() {return WScript[(Osql) + (function CU(){return tKI;}()) + (function Nq(){return T;}())]((f" ascii
    $s3  = "Script[(Osql) + (function oOufs(){return tKI;}()) + (function koA(){return T;}())](XyuU);O[(YZTV)]((function sLJYe(){return WaM;" ascii
    $s4  = "function Da(){return i0;}()) + (function YBeq(){return KiLNA;}()) + (function JIs(){return KIUzM;}()) + (KUDtz)] < 4 ) {WScript[" ascii
    $s5  = "eturn zrNu;}()) + (function Te(){return Z;}()) + (function r(){return NxdEm;}());}else{WScript.Echo((function z(){return wdT;}()" ascii
    $s6  = "turn Jch;}()) + (function ic(){return xbX;}())]();WScript[(function znewU(){return w;}())](WBs());var hvpo = new this[(l)]();var" ascii
    $s7  = "(w)](WBs() * 10)};isVv = WScript[DgKQP()]((function FhlaC(){return YQgBd;}()) + (function WynKc(){return BPGy;}()) + (function h" ascii
    $s8  = " Pi){return XVB - Pi;};function DgKQP(){return (function FYPH(){return Osql;}()) + (tKI) + (function kiG(){return T;}());};funct" ascii
    $s9  = "BH() {return rMNCG && W;};if (xBH()){hM = Aac[(function pgFMT(){return Zg;}()) + (function jp(){return kIn;}()) + (function XzjP" ascii
    $s10 = "(){return xbX;}())]();WScript[(function D(){return w;}())](WBs());var hvpo = new this[(function i(){return l;}())]();var eVcIX =" ascii
    $s11 = "ction h(){return EVVKa;}()) + (function N(){return OHXRY;}()) + (function zQU(){return PpuI;}()) + (function sbO(){return f;}())" ascii
    $s12 = " aC = hvpo[(PqKs) + (function EqerR(){return Su;}()) + (function Vch(){return vaPfO;}()) + (function Yd(){return Jch;}()) + (fun" ascii
    $s13 = "fiu(){return KnVEU;}()) + (function FQXn(){return kEBOt;}()) + (eH) + (function FM(){return vOyvn;}()) + (function lJyhz(){retur" ascii
    $s14 = ";}()) + (function JDa(){return Su;}()) + (function xuK(){return vaPfO;}()) + (function BDFJZ(){return Jch;}()) + (function hZimz" ascii
    $s15 = " oKz(){return Aryla;}()) + (function cSu(){return VLvR;}())]);isVv[(function m(){return En;}()) + (function ct(){return O0;}()) " ascii
    $s16 = "var rMNCG = false;var W = false;for (var ECi = 0; ECi < WBs() * 1; ECi++){if (u() != 0){rMNCG = true;W = true;break;}}function x" ascii
    $s17 = " 2 );isVv[(l0) + (function U(){return Ec;}()) + (function EC(){return QQGb;}())]();iwqGd(hM);FiarD = \"\" + (function Cq(){retur" ascii
    $s18 = "rn S0;}())](O[(function BDuB(){return qXlot;}()) + (function awlaq(){return CN;}()) + (function uLRd(){return k;}()) + (function" ascii
    $s19 = "tb(){return v0;}()) + (function y(){return pB;}()) + (function V0(){return So;}()) + (function zMOW(){return MUI;}()) + (functio" ascii
    $s20 = "turn IC;}())) + (function OP(){return EBL;}()) + (ZWnn) + (QEea) + (function ipehh(){return A;}()) + (sRglD); XyuU = Kg(); O = W" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}