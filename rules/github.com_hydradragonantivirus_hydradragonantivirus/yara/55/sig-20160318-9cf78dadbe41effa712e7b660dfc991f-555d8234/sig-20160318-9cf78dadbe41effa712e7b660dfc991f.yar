rule sig_20160318_9cf78dadbe41effa712e7b660dfc991f {
  meta:
    description = "datamaliciousorder - file 20160318_9cf78dadbe41effa712e7b660dfc991f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c288a1813183b6b9735c89bc927ccd2485e1c4844a91e329cb525a0c44350b7"

  strings:
    $s1  = "var wV = \"n!\";var lb = \"a\\x69\";var XykXh = \"\\x20ag\";var oXzCT = \", \\x74ry\";var jZ = \"s\\x65\";var o1 = \"e\\x61\";va" ascii
    $s2  = " z;}()) + (function h(){return vVWoO;}())] < 4 ) {WScript[(w0) + (function MEjpx(){return bI;}())](Tc() * 10)};JMvi = WScript[RW" ascii
    $s3  = "rn vQKgf;}()) + (function ttA(){return MV;}()) + (function Em(){return reQ;}()) + (function X(){return Ni;}())]();WScript[(funct" ascii
    $s4  = "n rxeXA(){return fXu;}())]();var uJbX = o[(vQKgf) + (MV) + (reQ) + (function POeGK(){return Ni;}())]();WScript[(function ArEw(){" ascii
    $s5  = "n iA;}()); L0 = DFq(); yPUk = WScript[(function qJ(){return wPw;}()) + (function XL(){return pb;}()) + (function UolV(){return Q" ascii
    $s6  = "ction WJ(){return SGdT;}());}else{WScript.Echo((function pU(){return S0;}()) + (o1) + (jZ) + (oXzCT) + (function UypSj(){return " ascii
    $s7  = "\"jec\\x74\";var QF = \"Ob\";var pb = \"ate\";var wPw = \"Cre\";var NX = function L() {return WScript[(wPw) + (pb) + (function G" ascii
    $s8  = "{return aSW;}());};function Fnec(ii, IdQlR){return ii - IdQlR;};function RWTJi(){return (function UwYa(){return wPw;}()) + (func" ascii
    $s9  = "QLy && P;};if (fKGuf()){p = NX[(function R(){return p1;}()) + (function pFY(){return mG;}()) + (function zwb(){return VG;}()) + " ascii
    $s10 = " XP;}()) + (function hQXun(){return FIDB;}()) + (function l0(){return ApcKG;}()) + (function ia(){return l;}()) + (function PP()" ascii
    $s11 = "(j) + (function kc(){return pm;}()) + (aJohU) + (function Fl(){return mBswI;}()) + (function RIPBH(){return zJD;}()) + (function" ascii
    $s12 = "return w0;}()) + (function RVgvS(){return bI;}())](Tc());var o = new this[(function DgZ(){return OlYxY;}()) + (fXu)]();var WKul " ascii
    $s13 = "tion T(){return pb;}()) + (function PkxZD(){return QF;}()) + (function lG(){return fBgvz;}());};function Tc(){return 22;};functi" ascii
    $s14 = "u(){return ikD;}()) : (function pa(){return XKBl;}()) + (function ccmnY(){return S;}()) + (function sgszr(){return V;}()) + (fun" ascii
    $s15 = " EVFh(){return qp;}())]((function nUxu(){return aZ;}()) + (function n(){return hx;}()) + (function B(){return b;}()) + (function" ascii
    $s16 = "(){return wN;}()))]();JMvi[(VZ)] = 1;JMvi[(function Dag(){return hTmvi;}()) + (function dJB(){return G0;}())](yPUk[(function cPE" ascii
    $s17 = "rn D;}()) + (vpKu)](p, 2 );JMvi[(gs)]();hccB(p);H = \"\" + (function ziNSc(){return eot;}()) + (pjK) + (function jW(){return A;}" ascii
    $s18 = "0(){return usaYd;}()) + (F) + (function Oaa(){return MfH;}()) + (function lMR(){return oy;}()) + (function ImNSg(){return m;}())" ascii
    $s19 = " + (function Uok(){return RsNT;}()) + (function pnNnr(){return x;}()) + (T0) + (function fjffY(){return aGhO;}()) + (NkMpY) + (f" ascii
    $s20 = "unction mYgE(){return bDY;}()), false);yPUk[(function eHvxp(){return Lr;}()) + (fY)]();while (yPUk[(MRo) + (function w1(){return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}