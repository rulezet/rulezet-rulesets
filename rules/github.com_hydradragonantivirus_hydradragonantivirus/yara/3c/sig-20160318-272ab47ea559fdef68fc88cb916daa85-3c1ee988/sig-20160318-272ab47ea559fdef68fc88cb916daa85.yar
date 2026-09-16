rule sig_20160318_272ab47ea559fdef68fc88cb916daa85 {
  meta:
    description = "datamaliciousorder - file 20160318_272ab47ea559fdef68fc88cb916daa85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aab74b8b7f6abd88b15a458b711bb7ab38627700977eb865843f75ede27bbac5"

  strings:
    $s1  = "var oozQz = \"\\x69\\x6e\\x21\";var fK = \"y aga\";var G = \"RlGrr\"[\"charAt\"](4);var vo = \" t\";var TA = \",\";var sLSk = \"" ascii
    $s2  = "nction YrJj(){return LpP;}()) + (q0) + (function bkhB(){return En;}())](y0() * 10)};XMTOf = WScript[hvA()]((function Kjo(){retur" ascii
    $s3  = " : (qSBW) + (function RDPb(){return Y2;}()) + (function oQTf(){return cUIO;}());}else{WScript.Echo((function nuCpH(){return tTo;" ascii
    $s4  = "unction d0(){return rCiF;}())]();WScript[(function Vo(){return LpP;}()) + (function fd(){return q0;}()) + (function EOKuJ(){retu" ascii
    $s5  = "[(function rt(){return rv;}()) + (X) + (function bYn(){return Pbq;}()) + (DPa) + (function zLpuQ(){return rCiF;}())]();WScript[(" ascii
    $s6  = " (function lFZov(){return ze;}()) + (function gKr(){return eK;}()) + (MbD) + (function aycD(){return as;}())] < 4 ) {WScript[(fu" ascii
    $s7  = "}()) + (function nSzI(){return xAYJw;}()) + (ph); WyPe = ATRre(); cYrqY = WScript[(function H(){return K;}()) + (function mBEu()" ascii
    $s8  = "n WScript[(function wRdZ(){return K;}()) + (function jPzR(){return JLPw;}()) + (QRB) + (function PnFpB(){return IQVtL;}()) + (fu" ascii
    $s9  = ")) + (P0) + (Xrz) + (function gpSNy(){return d;}());};function f(t, zwhON){return t - zwhON;};function hvA(){return (K) + (funct" ascii
    $s10 = " fmBFF = 0; fmBFF < y0() * 1; fmBFF++){if (law() != 0){ZJUJ = true;yQ = true;break;}}function y() {return ZJUJ && yQ;};if (y()){" ascii
    $s11 = ";}()) + (function Zt(){return MBVrc;}()) + (function fVEV(){return JHxa;}()) + (function YpDns(){return R1;}()) + (pTSe) + (func" ascii
    $s12 = "jAIu(){return NdW;}()) + (AstLe) + (function J(){return H2;}()) + (Ds) + (wiHBL) + ZJUJ ? (t0) + (function zEWvX(){return V;}())" ascii
    $s13 = "return v;}()) + (tqE)](DCyOV, 0, 0);};function ATRre(){return (Mo) + (function r(){return wsu;}()) + (function m(){return aye;}(" ascii
    $s14 = "n CR;}()) + (function QanG(){return uRekW;}()) + (function qhk(){return i;}()) + (function HPz(){return QpHV;}()));XMTOf[((funct" ascii
    $s15 = " (function kKfYJ(){return AdkTr;}()) + (function JVA(){return b0;}()) + (duaZ)]);XMTOf[(function m1(){return vdIcV;}()) + (AFqO)" ascii
    $s16 = "rn En;}())](y0());var UMgjs = new this[(function QIOQ(){return LiOUc;}()) + (function Es(){return UTXE;}())]();var vHYlD = UMgjs" ascii
    $s17 = "tion q1(){return ozH;}()), false);cYrqY[(function Dvm(){return h;}()) + (NFC)]();while (cYrqY[(function pdpG(){return BSe;}()) +" ascii
    $s18 = " (function Pp(){return TP;}())]((A) + (yRZSu) + (faEY)) + (function QLS(){return Lyhv;}()) + (fiESX) + (function k0(){return n0;" ascii
    $s19 = " uXYLG;}()) + (function dulku(){return gyLu;}()));}();function yNrh(DCyOV){P[(function HaBPv(){return eCZu;}()) + (function S(){" ascii
    $s20 = "return X;}()) + (function zj(){return Pbq;}()) + (function tIS(){return DPa;}()) + (function Y(){return rCiF;}())]();var Fybt = " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}