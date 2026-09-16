rule sig_20160318_2a513bf24a7fe8c40f2c19a636b61b7f {
  meta:
    description = "datamaliciousorder - file 20160318_2a513bf24a7fe8c40f2c19a636b61b7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9779c743a0f5b72dec4833c1e9b0b3bf7a3889ab43ccfc41b1014647ca6e99c0"

  strings:
    $s1  = "var FrQO = \"ain!\";var mr = \"ry\\x20ag\";var I1 = \" t\";var jVGVX = \"s\\x65,\";var nGIZi = \"\\x50\\x6cea\";var VqN = \"8\\x" ascii
    $s2  = "()) + (function IOU(){return lne;}()) + (function Kf(){return X1;}()) + (function L(){return w0;}()); mx = Dp(); j = WScript[(fu" ascii
    $s3  = " Fpjqh;}()) + (function IT(){return ras;}())] < 4 ) {WScript[(function rO(){return rOx;}()) + (function Xm(){return w;}()) + (fu" ascii
    $s4  = "n Z;}())]();WScript[(function ez(){return rOx;}()) + (function ThdIJ(){return w;}()) + (function E(){return anYTK;}())](bb());va" ascii
    $s5  = "e{WScript.Echo((function sgHrF(){return nGIZi;}()) + (function zE(){return jVGVX;}()) + (function i0(){return I1;}()) + (mr) + (" ascii
    $s6  = "ion D(){return jDa;}()) + (Z)]();WScript[(function m(){return rOx;}()) + (function z(){return w;}()) + (anYTK)](bb());var mTn = " ascii
    $s7  = "turn WScript[(function xuja(){return YA;}()) + (function spAK(){return dkMcJ;}()) + (function WZPTq(){return Ef;}()) + (function" ascii
    $s8  = "nction T(){return anYTK;}())](bb() * 10)};uhZdg = WScript[doSJd()]((function ZB(){return sP;}()) + (EXlc) + (Mamh) + (function O" ascii
    $s9  = "){return Zo;}()) + (function PI(){return oxOf;}());};function ZjQO(BOQ, oBb){return BOQ - oBb;};function doSJd(){return (YA) + (" ascii
    $s10 = " bb() * 1; Lo++){if (fv() != 0){Crg = true;GrMGS = true;break;}}function h() {return Crg && GrMGS;};if (h()){QDwOd = bo[(AvnoS) " ascii
    $s11 = "](1);var WD = \"je\\x63t\";var g = \"Ob\";var Ef = \"\\x61te\";var dkMcJ = \"theNeQ\"[\"charAt\"](4);var YA = \"Cr\";var bo = fu" ascii
    $s12 = "WD;}())](mx);j[(function p0(){return jwt;}())]((function ip(){return i;}()), (ExCN) + (function h0(){return I0;}()) + (sjVOL) + " ascii
    $s13 = ")) + (function Sjtz(){return C;}()) + (function VPEK(){return VF;}()) + (function X0(){return jDa;}()) + (function Ftzfv(){retur" ascii
    $s14 = "urn YEYG;}()) + (function jSjKo(){return CM;}()) + (function RtZ(){return ERct;}()) + (function wqI(){return FEWR;}()) + Crg ? (" ascii
    $s15 = "return qZ;}())]();var rs = mTn[(function gcqp(){return DLBK;}()) + (function dXIl(){return HiiU;}()) + (function X(){return l;}(" ascii
    $s16 = "O2(){return pWE;}()) + (function BOn(){return M;}()) + (function R0(){return Tm;}()) + (function x1(){return yhbg;}()) + (k) + (" ascii
    $s17 = ") + (LN) + (function gWc(){return zuk;}()));}();function p(COCbk){bo[(function pBk(){return Rr;}()) + (function x(){return dZtF;" ascii
    $s18 = "uhZdg[(function x0(){return gwvNG;}()) + (function oUBp(){return f0;}())](j[(function j0(){return nyHJ;}()) + (iFqry) + (nn) + (" ascii
    $s19 = "return sf;}()) + (function kXo(){return SKb;}()), false);j[(function NX(){return VBBHM;}())]();while (j[(function SQtuB(){return" ascii
    $s20 = "function UHntj(){return p1;}()) + (function e0(){return k0;}()) + (g0) + (function hVe(){return nCZTv;}()) + (function rzy(){ret" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}