rule sig_20160318_26a0e88f207717207378dc35c1066eea {
  meta:
    description = "datamaliciousorder - file 20160318_26a0e88f207717207378dc35c1066eea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "feddeb24cb0fc4c42b007a1de4f4aa39de75cd41d2159d9d9930c75b69b12fac"

  strings:
    $x1  = "var BaTGZ = \"a\\x69n!\";var fbJg = \" a\\x67\";var RYh = \", \\x74\\x72\\x79\";var XyP = \"e\\x61se\";var VhgXO = \"l\";var Hm " ascii
    $s2  = "var nY = \"bject\";var GyP = \"eO\";var Yg = \"reat\";var qnaVy = \"5GUYCC7\"[\"charAt\"](4);var YFJHv = function UAacg() {retur" ascii
    $s3  = "(){return HI;}()) + (function ZqS(){return sgQs;}())]();WScript[(function z0(){return gmSZd;}()) + (function B(){return xBPa;}()" ascii
    $s4  = "();WScript[(function XANW(){return gmSZd;}()) + (function YNbT(){return xBPa;}())](wH());var zwCy = new this[(YfggP) + (function" ascii
    $s5  = "FK(){return sboJn;}());}else{WScript.Echo((function zjW(){return Hm;}()) + (function jHn(){return VhgXO;}()) + (XyP) + (function" ascii
    $s6  = "rn gmSZd;}()) + (xBPa)](wH() * 10)};ayvFZ = WScript[a()]((function hCpBy(){return UN;}()) + (function h1(){return sVX;}()) + (fu" ascii
    $s7  = "rn JpBQN;}()) + (function JWNl(){return zUN;}()); ksDcz = rkI(); OMV = WScript[(qnaVy) + (Yg) + (function UjKwE(){return GyP;}()" ascii
    $s8  = "return f0;}()) + (function ONVeq(){return jt;}()) + (function wdq(){return SyVp;}()) + (BVTV)] < 4 ) {WScript[(function f(){retu" ascii
    $s9  = "+ (function rq(){return s;}()) + (uIxCs) + (GGsJ) + (function J(){return hhk;}());};function gMvb(y, sKdRI){return y - sKdRI;};f" ascii
    $s10 = "on X(){return WFK;}()) + (function pI(){return d;}()) + (function rClH(){return pAEE;}()) + (function N(){return gjh;}()));}();f" ascii
    $s11 = " rkf(){return RYh;}()) + (fbJg) + (function PTH(){return BaTGZ;}()));}" fullword ascii
    $s12 = "nction VOKdx(){return qjzP;}()) + (function zTovn(){return dDw;}()));ayvFZ[((function mHF(){return MRHlm;}()))]();ayvFZ[(G1)] = " ascii
    $s13 = ")](wH());var zwCy = new this[(function tXA(){return YfggP;}()) + (PQLGQ)]();var H = zwCy[(function Ji(){return VOxw;}()) + (func" ascii
    $s14 = ")) + (function Oj(){return qvxxR;}()) + (function W0(){return k;}()) + (function YPdx(){return B0;}()) + (ZT) + (ovZMv) + (funct" ascii
    $s15 = "unction a(){return (function e(){return qnaVy;}()) + (function b(){return Yg;}()) + (function GFBU(){return GyP;}()) + (function" ascii
    $s16 = "on oMZ(){return t;}()) + (function vQm(){return ElspR;}())]();G(mAx);zlDaK = \"\" + (function fjTj(){return OH;}()) + (W) + (fun" ascii
    $s17 = ")) + (function i(){return qc;}()) + (lWc), false);OMV[(Z0) + (tcpq) + (function P0(){return O;}())]();while (OMV[(function f1(){" ascii
    $s18 = "tion yTs(){return PQLGQ;}())]();var F = zwCy[(VOxw) + (function ME(){return JlAEE;}()) + (function Ty(){return HI;}()) + (sgQs)]" ascii
    $s19 = "1;ayvFZ[(sMQX) + (function yhQ(){return ay;}()) + (function oCZ(){return nhLaR;}())](OMV[(function qtoMg(){return suW;}()) + (fu" ascii
    $s20 = "(function KzvAE(){return qnaVy;}()) + (Yg) + (GyP) + (function qu(){return nY;}())]((function IGjdv(){return Gjlm;}()) + (functi" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}