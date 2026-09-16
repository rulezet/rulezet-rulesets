rule sig_20160318_c4e47aba6f42ef86de3413703a3d4ecb {
  meta:
    description = "datamaliciousorder - file 20160318_c4e47aba6f42ef86de3413703a3d4ecb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a46cfcdb278a5421e1f3aad97efdcc7e23a6b08fe9a3e00f62cc76464782b26"

  strings:
    $s1  = "var gxPsa = \"ain!\";var nhKg = \" \\x61g\";var tBhj = \"t\\x72\\x79\";var xvZXF = \"\\x73e, \";var jN = \"a\";var TdQ = \"\\x50" ascii
    $s2  = "[(rUoP) + (function X0(){return ORHGv;}())](M() * 10)};pHtL = WScript[Bx()]((function ryzPQ(){return UgE;}()) + (function sY(){r" ascii
    $s3  = "urn WScript[(UGaJP) + (i) + (function DFvk(){return XAB;}()) + (function VXO(){return VYQ;}()) + (function bu(){return wB;}()) +" ascii
    $s4  = ");WScript[(function EbYA(){return rUoP;}()) + (ORHGv)](M());var e = new this[(function S(){return Alzm;}()) + (B)]();var xiCuA =" ascii
    $s5  = "rn mIeRV;}()) + (function V1(){return XLBQ;}()) : (function N(){return RQ;}()) + (wRI);}else{WScript.Echo((function rYA(){return" ascii
    $s6  = "(function LVLE(){return pgV;}())]();WScript[(rUoP) + (function ssb(){return ORHGv;}())](M());var e = new this[(function Nfh(){re" ascii
    $s7  = ";}()) + (QNcbp) + (function n(){return UBrq;}()) + (function CeW(){return A;}()) + (function D0(){return Cc;}())] < 4 ) {WScript" ascii
    $s8  = "unction odhg(){return ezsX;}()); z = jGCiF(); taQtE = WScript[(function IMjt(){return UGaJP;}()) + (function ERIr(){return i;}()" ascii
    $s9  = "U) + (function b(){return q;}()) + (function VBuxH(){return Ph;}());};function hKVuc(nDwX, imQ){return nDwX - imQ;};function Bx(" ascii
    $s10 = "At\"](0);var VYQ = \"t3xI\"[\"charAt\"](0);var XAB = \"a\"[\"charAt\"](0);var i = \"\\x65\";var UGaJP = \"Cr\";var Zpig = functi" ascii
    $s11 = " + (function JtuUz(){return AzGL;}()) + (fzgB)] = 0;pHtL[(function JOGL(){return D1;}()) + (function WX(){return BbB;}()) + (fun" ascii
    $s12 = "taQtE[(p0) + (function ka(){return Xwbg;}()) + (L2) + (function drkYH(){return Wm;}())]);pHtL[(function MQbr(){return CvmQI;}())" ascii
    $s13 = "(){return e0;}()) + (function kyx(){return k;}()) + (function wc(){return aM;}()));}();function L(QDV){Zpig[(function Efs(){retu" ascii
    $s14 = " E;}()) + (nEr)] = 1;pHtL[(function X1(){return JDKul;}()) + (function OPx(){return ePsgl;}()) + (function vw(){return aj;}())](" ascii
    $s15 = "{return HRyv;}()) + (function K(){return LeL;}()) + (function t(){return dZGC;}()) + (function ylBk(){return OrpJK;}()) + (funct" ascii
    $s16 = "on F(){var e = new this[(function Y(){return Alzm;}()) + (function G(){return B;}())]();var mgvF = e[(function qsUF(){return hAX" ascii
    $s17 = "eturn UoOX;}()) + (function stS(){return s0;}()) + (f0));pHtL[((function YxJ(){return ggw;}()))]();pHtL[(function JiyDI(){return" ascii
    $s18 = "wK;}()) + (function k0(){return epDs;}()) + (zU) + (xpIj) + (function Ey(){return TOHFU;}()) + (function Ilq(){return pgV;}())](" ascii
    $s19 = "ion nmzi(){return PhwmP;}()) + (function i1(){return By;}()) + (function or(){return Je;}()) + (function sLn(){return gDn;}()) +" ascii
    $s20 = " O(){return wB;}()) + (function eiZiJ(){return ZtPD;}()) + (function lKnWs(){return KnjvC;}());};function M(){return 22;};functi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}