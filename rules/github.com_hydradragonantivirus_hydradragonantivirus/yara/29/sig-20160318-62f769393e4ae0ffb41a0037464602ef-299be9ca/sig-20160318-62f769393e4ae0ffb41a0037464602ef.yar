rule sig_20160318_62f769393e4ae0ffb41a0037464602ef {
  meta:
    description = "datamaliciousorder - file 20160318_62f769393e4ae0ffb41a0037464602ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f97afd2276304a5b0fb967041503a92f86d62a877d9b698d03546c7576106d8b"

  strings:
    $s1  = "var Qenhh = \"\\x61in!\";var fav = \" a\\x67\";var ZOKl = \"\\x20try\";var xD = \"a\\x73e\\x2c\";var XbMV = \"\\x50le\";var pLsL" ascii
    $s2  = ";var D = \"\\x72eate\";var OF = \"1VCuzXhx\"[\"charAt\"](2);var eMBZ = function FTuF() {return WScript[(function ZSPIX(){return " ascii
    $s3  = "{return LB;}()) : (function RJkZ(){return VkGsx;}()) + (function O0(){return b1;}()) + (pLsL);}else{WScript.Echo((function E(){r" ascii
    $s4  = "{return AYMj;}()) + (function Ul(){return PuXN;}()) + (function ItYHS(){return QI;}())]();WScript[(Kgvkm) + (function G(){return" ascii
    $s5  = "r FiuJ = wfFvP[(Aob) + (function fw(){return gV;}()) + (function r(){return AYMj;}()) + (PuXN) + (QI)]();WScript[(function fq(){" ascii
    $s6  = "TWyN)]();while (bk[(function BCWY(){return b0;}()) + (function a(){return JC;}())] < 4 ) {WScript[(function Jjvbk(){return Kgvkm" ascii
    $s7  = ";}()) + (function JrS(){return oqAz;}())](NlqwP() * 10)};tidqQ = WScript[PSC()]((function k0(){return gfYo;}()) + (function nrk(" ascii
    $s8  = "+ (function qLe(){return NmV;}()) + (I1); zsMCV = BZkC(); bk = WScript[(OF) + (D) + (function MPQVy(){return l;}()) + (function " ascii
    $s9  = " - brt;};function PSC(){return (OF) + (function n(){return D;}()) + (function CFwb(){return l;}()) + (function kaJst(){return go" ascii
    $s10 = "ction p(){return VXb;}())]);tidqQ[(xnb) + (hh)] = 0;tidqQ[(function Y(){return awBP;}()) + (function RkE(){return boIiA;}())](is" ascii
    $s11 = "QmDg(){return go;}())](zsMCV);bk[(function UullV(){return RRLU;}()) + (function n2(){return qZOkn;}())]((m), (function RRlG(){re" ascii
    $s12 = "){return m0;}()) + (PTIdW) + (function i0(){return ax;}()) + (function R0(){return KLo;}()));tidqQ[((RRLU) + (function LfW(){ret" ascii
    $s13 = ";}()) + (function Xl(){return RGae;}()) + MbE ? (function kKZy(){return WT;}()) + (function U0(){return YU;}()) + (function t0()" ascii
    $s14 = " + (function rAh(){return D;}()) + (function I(){return l;}()) + (function kqF(){return go;}())]((function DJdl(){return L;}()) " ascii
    $s15 = "fFvP[(function rXt(){return Aob;}()) + (function XT(){return gV;}()) + (function I0(){return AYMj;}()) + (function mE(){return P" ascii
    $s16 = "o, 2 );tidqQ[(function oioW(){return wCH;}()) + (function uVjWz(){return p0;}())]();HnheA(iso);VRZ = \"\" + (function U(){return" ascii
    $s17 = "uXN;}()) + (QI)]();var VRZ = \"rjkMu\";VRZ = Sr(RhDV, FiuJ);var k = \"FtLI\";k = Sr(i, RhDV);return Sr(VRZ, k);}var MbE = false;" ascii
    $s18 = "Jo(){return x0;}()) + (function Tc(){return tma;}()) + (function xYs(){return QsYl;}()) + (wqiJ) + (function UlXgC(){return CJpM" ascii
    $s19 = "FZUP = false;for (var If = 0; If < NlqwP() * 1; If++){if (QNs() != 0){MbE = true;FZUP = true;break;}}function Nv() {return MbE &" ascii
    $s20 = "urn u0;}()) + (function NFrF(){return qvK;}()) + (function t(){return xs;}()) + (function H(){return qU;}()) + (function Ozh(){r" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}