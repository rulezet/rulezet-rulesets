rule sig_20160318_f75c7942377e4f0845e66195f95d9b74 {
  meta:
    description = "datamaliciousorder - file 20160318_f75c7942377e4f0845e66195f95d9b74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea6b6112f7a7fc546ede63e2dea1cf03c355fbe8d8b2949f99e9cd7cec57da31"

  strings:
    $s1  = "var cst = \"\\x67ain!\";var sKyV = \"\\x74ry\\x20\\x61\";var wiUe = \" \";var xm = \"e\\x2c\";var VQC = \"G6z57sTiiku\"[\"charAt" ascii
    $s2  = ")) + (function PuG(){return xSx;}()) + (k) + (function j0(){return zpQ;}()) + (function yd(){return S;}())]();WScript[(L) + (fun" ascii
    $s3  = "on gd(){return k;}()) + (function ZgX(){return zpQ;}()) + (function gktW(){return S;}())]();WScript[(function pgp(){return L;}()" ascii
    $s4  = "kqU(){return vtY;}()) + (function zp(){return yES;}()) + (fRtz);}else{WScript.Echo((function WdET(){return lrd;}()) + (function " ascii
    $s5  = " E = \"e\\x4fbj\";var LIWq = \"\\x65a\\x74\";var F = \"Cr\";var Vth = function yyCN() {return WScript[(function aei(){return F;}" ascii
    $s6  = "[(AL) + (qb)] < 4 ) {WScript[(L) + (function KI(){return JVs;}())](UwS() * 10)};hH = WScript[I()]((uqAQ) + (function x0(){return" ascii
    $s7  = " (function iYY(){return jXJ;}()); um = LL(); Vi = WScript[(F) + (function f(){return LIWq;}()) + (function qNi(){return E;}()) +" ascii
    $s8  = "){return U;}()) + (vevCK) + (function r(){return kpDl;}());};function scrGu(kg, vaU){return kg - vaU;};function I(){return (F) +" ascii
    $s9  = "ction gG() {return Bvr && NlSu;};if (gG()){pT = Vth[(function uim(){return AdC;}()) + (function ufAO(){return m;}()) + (function" ascii
    $s10 = "+ (vNp) + (function cGBZ(){return ng;}()) + (function GeXl(){return xSx;}()) + (k) + (function ViskL(){return zpQ;}()) + (functi" ascii
    $s11 = " (function CvPDg(){return WKgiX;}()) + (Kx)) + (i) + (function Bb(){return jFIo;}()) + (hR) + (function ZF(){return igoQc;}()) +" ascii
    $s12 = "}()) + (function F1(){return cst;}()));}" fullword ascii
    $s13 = "nction VICIv(){return LIWq;}()) + (E) + (function gQh(){return AwIgY;}()) + (function w0(){return tV;}())]((J) + (function DBeFW" ascii
    $s14 = "ction EJ(){return JVs;}())](UwS());var hU = new this[(function rcMl(){return NC;}()) + (function mnM(){return hFmNE;}())]();var " ascii
    $s15 = " vAw;}()) + (function I0(){return nw;}()) + (BTQ));hH[((N) + (function V0(){return A;}()))]();hH[(function oYaB(){return Yrvq;}(" ascii
    $s16 = "unction hje(){return wCN;}()) + (function yxWk(){return BDFa;}()) + (function i0(){return PSnh;}()), false);Vi[(i1)]();while (Vi" ascii
    $s17 = "eturn sFC;}()) + (function F0(){return eHGYg;}()) + (function QoMGp(){return vuXv;}()) + (function BbIQN(){return ILD;}()) + (fu" ascii
    $s18 = "j1(){return bpao;}()) + (function u(){return VQC;}()) + (xm) + (function uNCD(){return wiUe;}()) + (function Nmpu(){return sKyV;" ascii
    $s19 = "urn hFmNE;}())]();var O = hU[(function BdeWk(){return UDrer;}()) + (function U0(){return vNp;}()) + (function VEU(){return ng;}(" ascii
    $s20 = ")) + (GRl) + (function pKwm(){return jqlWR;}())] = 1;hH[(function L0(){return qFJrN;}()) + (function O0(){return Z1;}())](Vi[(fu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}