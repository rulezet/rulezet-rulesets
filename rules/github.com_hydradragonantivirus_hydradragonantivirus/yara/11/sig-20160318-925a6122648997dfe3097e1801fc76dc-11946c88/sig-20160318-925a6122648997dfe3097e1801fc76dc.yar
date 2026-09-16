rule sig_20160318_925a6122648997dfe3097e1801fc76dc {
  meta:
    description = "datamaliciousorder - file 20160318_925a6122648997dfe3097e1801fc76dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d882bf39c41ddba7ffc8ade8a064780a1e6624ff5f3cdf2ae3adebab7e38b52"

  strings:
    $s1  = "var okLDQ = \"cFbAb!1gty\"[\"charAt\"](5);var yDz = \"in\";var mmPJ = \"y \\x61ga\";var NzC = \"e\\x2c tr\";var MhN = \"s\";var " ascii
    $s2  = " - S;};function Wkbd(){return (M) + (function CoFT(){return vCX;}()) + (function CqcGg(){return xEm;}()) + (function Gq(){return" ascii
    $s3  = "se{WScript.Echo((function Jy(){return c;}()) + (mxZ) + (function qbPRv(){return MhN;}()) + (function Aoi(){return NzC;}()) + (mm" ascii
    $s4  = "E = sIIm(); FIbn = WScript[(function uEnfR(){return M;}()) + (vCX) + (function KW(){return xEm;}()) + (function DjQi(){return QY" ascii
    $s5  = "Script[(function zVZG(){return gLC;}()) + (function agyr(){return tz;}())](YmBTf());var TYNN = new this[(QFQT)]();var L = TYNN[(" ascii
    $s6  = "e\";var vCX = \"eate\\x4f\";var M = \"Cr\";var Lq = function rUcH() {return WScript[(function IJ(){return M;}()) + (function yhr" ascii
    $s7  = ") + (Gq0) + (Coo) + (function RoqsC(){return Xntep;}()) + (ApSpa) + (function ckG(){return GKX;}())]();WScript[(function T(){ret" ascii
    $s8  = "eturn rLv;}()) + (oCh)] < 4 ) {WScript[(gLC) + (function erw(){return tz;}())](YmBTf() * 10)};Kt = WScript[Wkbd()]((function xsi" ascii
    $s9  = "wbt() {return dCcC && WsSpi;};if (WGwbt()){xEB = Lq[(function Cdjw(){return xzNVH;}()) + (function SLZ(){return nKGMb;}()) + (up" ascii
    $s10 = "){return dV;}()) + (OI)] = 0;Kt[(fDwip) + (function DOeFW(){return eTu;}()) + (function ColK(){return db;}()) + (a) + (function " ascii
    $s11 = "function yeNi(){return C;}()) + (Gq0) + (function CNVl(){return Coo;}()) + (function HtESg(){return Xntep;}()) + (function BqB()" ascii
    $s12 = ");var t0 = \"E\\x4d\";var bUuv = \"sSTVc68\"[\"charAt\"](2);var F = \"v%n\"[\"charAt\"](1);var B = \"ings\";var t = \"tr\";var T" ascii
    $s13 = "ction vFEGO(){return WANw;}()));Kt[((U0) + (function Rb(){return DgOTB;}()))]();Kt[(function d0(){return lrXzM;}()) + (function " ascii
    $s14 = "fkIzi(){return y0;}())] = 1;Kt[(function lZ(){return P;}())](FIbn[(function zd(){return Avqzw;}()) + (function F0(){return Itd;}" ascii
    $s15 = "U1(){return P0;}())](xEB, 2 );Kt[(function Gg(){return QSeO;}()) + (YePo)]();CFtR(xEB);y = \"\" + (function sv(){return DkHF;}()" ascii
    $s16 = "{return ApSpa;}()) + (GKX)]();var y = \"V\";y = R(kqyCj, p);var ste = \"nWX\";ste = R(L, kqyCj);return R(y, ste);}var dCcC = fal" ascii
    $s17 = "()) + (function b1(){return SVVB;}()) + (function Jd(){return EcVmG;}())]);Kt[(function AwE(){return SxQ;}()) + (function BHgFb(" ascii
    $s18 = "MdGd(){return vvDr;}()) + (function N(){return VyXM;}()) + (function jqqi(){return LbzZ;}()) + (function C0(){return WUF;}()) + " ascii
    $s19 = "Qbr;}())](qE);FIbn[(function b0(){return U0;}()) + (DgOTB)]((function IL(){return v0;}()), (QS) + (function h0(){return B0;}()) " ascii
    $s20 = "+ (function ma(){return huYRe;}()) + (function xfm(){return Xhlp;}()) + (function I0(){return uKWMB;}()) + (function xsZ(){retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}