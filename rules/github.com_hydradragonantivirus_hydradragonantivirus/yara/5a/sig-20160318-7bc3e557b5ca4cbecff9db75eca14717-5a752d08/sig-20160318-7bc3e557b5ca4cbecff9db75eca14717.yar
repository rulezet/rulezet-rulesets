rule sig_20160318_7bc3e557b5ca4cbecff9db75eca14717 {
  meta:
    description = "datamaliciousorder - file 20160318_7bc3e557b5ca4cbecff9db75eca14717.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05a14e530b289ca83dd65b9f12ccacd00e67abb081948b4633e47ed07ef34307"

  strings:
    $x1  = "var BqgpU = \"\\x67ain!\";var dOJP = \"\\x74ry \\x61\";var tdtAX = \"s\\x65, \";var n = \"\\x61\";var PlAW = \"le\";var pNX = \"" ascii
    $s2  = "CR;}())](Wj() * 10)};EVwT = WScript[lj()]((function PmYiS(){return uWxP;}()) + (function KC0(){return Y0;}()) + (function c0(){r" ascii
    $s3  = " dTc(){return IF;}()) + (function LnSEZ(){return kWnaU;}()) + (function J(){return VnAh;}())]();WScript[(function gG(){return bJ" ascii
    $s4  = "n q(){return Dy;}())] < 4 ) {WScript[(function Bc(){return bJD;}()) + (function wfmiv(){return NsE;}()) + (function iH(){return " ascii
    $s5  = ") + (function jCMJv(){return g;}()); xhTRp = ofId(); oRVt = WScript[(kcZde) + (function NaDdB(){return Oddsr;}()) + (function tr" ascii
    $s6  = "var Oddsr = \"t\\x65\\x4f\";var kcZde = \"C\\x72ea\";var d = function DFat() {return WScript[(function xvqw(){return kcZde;}()) " ascii
    $s7  = "Z(){return acLPu;}()) + (Qx) : (function LP(){return vuD;}()) + (EE) + (ntWZp);}else{WScript.Echo((pNX) + (PlAW) + (function B()" ascii
    $s8  = "WnaU;}()) + (function DX(){return VnAh;}())]();WScript[(function cMUhR(){return bJD;}()) + (NsE) + (function TnNLS(){return CR;}" ascii
    $s9  = "return Mp;}()) + (fAM);};function N(TMr, qumc){return TMr - qumc;};function lj(){return (kcZde) + (function zd(){return Oddsr;}(" ascii
    $s10 = "= true;iz = true;break;}}function OdoEG() {return Sj && iz;};if (OdoEG()){m = d[(function mO(){return PmKJ;}()) + (function mv()" ascii
    $s11 = "x6fn\\x64s\";var IYGYF = \"l\\x69se\";var K = \"etMi\\x6c\";var lc = \"kgAY\"[\"charAt\"](1);var ELr = \"\\x44at\\x65\";var CR =" ascii
    $s12 = "y0(){return ihEIw;}()) + (ic)](xhTRp);oRVt[(Z0) + (function b2(){return fvmS;}())]((function al(){return PE;}()) + (cQNKR), (Mvb" ascii
    $s13 = "vM, Tem);return N(MMwH, MwF);}var Sj = false;var iz = false;for (var hdlhK = 0; hdlhK < Wj() * 1; hdlhK++){if (QfbqM() != 0){Sj " ascii
    $s14 = "{return n;}()) + (function c1(){return tdtAX;}()) + (function yp(){return dOJP;}()) + (function yIUf(){return BqgpU;}()));}" fullword ascii
    $s15 = "())](Wj());var wFu = new this[(function IgyH(){return QE;}()) + (function y(){return lGHJO;}())]();var Tem = wFu[(c) + (function" ascii
    $s16 = "tion ruWb(){return Oddsr;}()) + (function z(){return ihEIw;}()) + (function SkLw(){return ic;}())]((function nveQb(){return v;}(" ascii
    $s17 = "+ (function R(){return jML;}()) + (function KC(){return h;}()) + (function vdm(){return rhINB;}())]((function eV(){return u;}())" ascii
    $s18 = "w this[(function p(){return QE;}()) + (lGHJO)]();var nDXF = wFu[(function qv(){return c;}()) + (IF) + (function EatNF(){return k" ascii
    $s19 = "SN(SaRYe){d[(function Hss(){return ETj;}())](SaRYe, 0, 0);};function ofId(){return (function D(){return H;}()) + (function Vy(){" ascii
    $s20 = "CzyB(){return mpeCm;}()) + (function Dwz(){return u0;}()) + (Vs), false);oRVt[(function lKsf(){return rOwH;}()) + (function JL()" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}