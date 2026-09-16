rule sig_20160318_bd880955bbaab697d2c336344d36941e {
  meta:
    description = "datamaliciousorder - file 20160318_bd880955bbaab697d2c336344d36941e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1d668f66cf3c0008a056a9f9db6e6f64e65f218bba6edefc013f7f9695c9c52"

  strings:
    $s1  = "var tzib = \"in!\";var Clv = \"g\\x61\";var Q0 = \"y a\";var uB = \", t\\x72\";var Oz = \"e\";var nZl = \"Ple\\x61\\x73\";var bt" ascii
    $s2  = "else{WScript.Echo((nZl) + (Oz) + (uB) + (function kDjg(){return Q0;}()) + (Clv) + (function BUT(){return tzib;}()));}" fullword ascii
    $s3  = "b\\x6a\\x65\";var yuVa = \"teO\";var XI = \"Cre\\x61\";var hkXx = function tRqUT() {return WScript[(XI) + (function Cd(){return " ascii
    $s4  = "(); QTOaJ = WScript[(XI) + (function DpTv(){return yuVa;}()) + (function gFN(){return H;}()) + (function HPXsE(){return hs;}())]" ascii
    $s5  = "n oOnr;}()) + (function RUH(){return J;}())]();WScript[(function kOn(){return KTL;}()) + (yiX)](BGl());var ZXt = new this[(funct" ascii
    $s6  = "Se(){return hAJ;}()) + (function bPb(){return WZkJg;}()) + (function T(){return oOnr;}()) + (J)]();WScript[(KTL) + (function ruO" ascii
    $s7  = "n VWkz;}())] < 4 ) {WScript[(function YkVH(){return KTL;}()) + (function ekKG(){return yiX;}())](BGl() * 10)};DOJUu = WScript[d(" ascii
    $s8  = " + (EvCD);};function sA(F, JJL){return F - JJL;};function d(){return (function X(){return XI;}()) + (function ULRMa(){return yuV" ascii
    $s9  = "r && bF;};if (z()){xioEz = hkXx[(function eXs(){return lQ;}()) + (function JyL(){return SL;}()) + (UzD) + (LZE) + (OcTht) + (NbM" ascii
    $s10 = "67et\";var IH = \"\\x61te\";var FaRL = \"D\";var yiX = \"9pk\"[\"charAt\"](1);var KTL = \"Sle\\x65\";var J = \"\\x6ed\\x73\";var" ascii
    $s11 = "K;}()) + (function dBWaB(){return S0;}())] = 0;DOJUu[(function qY(){return vhTSN;}()) + (function Vk(){return Wa;}()) + (functio" ascii
    $s12 = "WqkW(){return HMQi;}()) + (function q(){return MoV;}()) + (uv) + (function KfclV(){return s;}()) + (function go(){return k0;}())" ascii
    $s13 = "f;}())) + (function vAT(){return q0;}()) + (O) + (function rKZ(){return c0;}()) + (function j0(){return sdOA;}()) + (x); lo = DO" ascii
    $s14 = ") + (H) + (function j(){return hs;}())]((function si(){return rvLMj;}()) + (ovy) + (function Pjcmi(){return m;}()));}();function" ascii
    $s15 = ")]((function GdjK(){return jMfm;}()) + (evgLU) + (function F0(){return BL;}()) + (function mGWbL(){return Jag;}()));DOJUu[((func" ascii
    $s16 = " G(){return Miol;}()) + (function gmJE(){return eG;}()) + (function jFSIk(){return cRHTU;}()) + (function X0(){return rDuLX;}())" ascii
    $s17 = " qn(D){hkXx[(dK) + (function za(){return vLJ;}())](D, 0, 0);};function DO(){return (function V(){return VktNI;}()) + (function j" ascii
    $s18 = "Xt[(function BEAtb(){return mxOd;}()) + (function nyY(){return atI;}()) + (hAJ) + (WZkJg) + (function IG(){return oOnr;}()) + (f" ascii
    $s19 = "uj(){return yiX;}())](BGl());var ZXt = new this[(function zHx(){return TyLii;}()) + (function h(){return okTq;}())]();var oy = Z" ascii
    $s20 = "(function x0(){return O0;}()) + (function MP(){return M;}()) + (function NWqz(){return u1;}()), false);QTOaJ[(function OOfF(){re" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}