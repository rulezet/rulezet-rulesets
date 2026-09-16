rule sig_20160318_cf5a300a80bed9ae9a66aefb6f81498e {
  meta:
    description = "datamaliciousorder - file 20160318_cf5a300a80bed9ae9a66aefb6f81498e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e8b10547f49459e919a7dc52bfd3065d3aa6c1b8d7d163d0408980c40b95d0f"

  strings:
    $s1  = "var K2 = \"Vjkh!D6SD\"[\"charAt\"](4);var loVK = \"in\";var Dmsm = \"a\";var A0 = \" a\\x67\";var jaPnJ = \"y\";var HzfJf = \"," ascii
    $s2  = "return WScript[(function kBK(){return swJH;}()) + (QIK) + (ZOFKA)]((function hVY(){return Imff;}()) + (function OuAVa(){return z" ascii
    $s3  = ") + (bx) + (function ENN(){return BwoP;}())] < 4 ) {WScript[(function lxeUH(){return gyeV;}()) + (function kX(){return i1;}()) +" ascii
    $s4  = "n tz;}()) + (function yw(){return Or;}());}else{WScript.Echo((DosG) + (function k1(){return OB;}()) + (function U(){return HzfJf" ascii
    $s5  = "tion rVj(){return C;}())]();WScript[(function Pu(){return gyeV;}()) + (function QEEk(){return i1;}()) + (function rbisJ(){return" ascii
    $s6  = "{return fs;}()) + (function JPJ(){return kl;}()) + (function th(){return YHsl;}()) + (GQV) + (xWs); Bo = NPn(); v = WScript[(fun" ascii
    $s7  = " (soUrr)](DH() * 10)};tUQ = WScript[nRz()]((wX) + (function f1(){return LPE;}()) + (function kFdq(){return QDnJP;}()) + (functio" ascii
    $s8  = "(){return HnGE;}())]();var DtdMo = GNZv[(function SyCK(){return kE;}()) + (m) + (hw) + (C)]();WScript[(function i2(){return gyeV" ascii
    $s9  = "+ (function u(){return e;}());};function EaXu(sx, noQaJ){return sx - noQaJ;};function nRz(){return (function EZjGY(){return swJH" ascii
    $s10 = "{return dXU && D;};if (oLq()){ywFFJ = vP[(LOzFI) + (function qPD(){return F;}()) + (function P(){return pZ;}()) + (function WWbH" ascii
    $s11 = "RcTID) + (function aM(){return YGyK;}()) + (KtHyQ)](ywFFJ, 2 );tUQ[(rf) + (function fTY(){return P0;}())]();WpMC(ywFFJ);k = \"\"" ascii
    $s12 = ";}()) + (QIK) + (function ThO(){return ZOFKA;}());};function DH(){return 22;};function SEqaO(){var GNZv = new this[(function ZEJ" ascii
    $s13 = ";}var dXU = false;var D = false;for (var w = 0; w < DH() * 1; w++){if (SEqaO() != 0){dXU = true;D = true;break;}}function oLq() " ascii
    $s14 = "urn yxy;}()) + (KHiG) + (function UZWK(){return Fj;}()) + (RXmM) + (function t(){return ALgx;}()), false);v[(function FTRdE(){re" ascii
    $s15 = "{return G;}())] = 1;tUQ[(function xeQv(){return zyR;}()) + (function aqpyU(){return bQC;}())](v[(function QASQf(){return Ur;}())" ascii
    $s16 = "unction odolw(){return suQb;}()) + (function De(){return zLQad;}()) + (function aF(){return R;}()) : (function CNW(){return ph;}" ascii
    $s17 = ";}()) + (function LD(){return jaPnJ;}()) + (function kkC(){return A0;}()) + (function zHXY(){return Dmsm;}()) + (loVK) + (functi" ascii
    $s18 = "eturn K;}())](uHn, 0, 0);};function NPn(){return (kV) + (function qw(){return Yix;}()) + (function bi(){return iUjVr;}()) + (d) " ascii
    $s19 = "hw) + (function FqSeG(){return C;}())]();var k = \"jcNj\";k = EaXu(iaafl, DtdMo);var Q = \"E\";Q = EaXu(XL, iaafl);return EaXu(k" ascii
    $s20 = " soUrr;}())](DH());var GNZv = new this[(function hzb(){return HnGE;}())]();var XL = GNZv[(kE) + (function i0(){return m;}()) + (" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}