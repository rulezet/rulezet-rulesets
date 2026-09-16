rule sig_20160318_bb308e08e0021d41d016da256cd9ae96 {
  meta:
    description = "datamaliciousorder - file 20160318_bb308e08e0021d41d016da256cd9ae96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "392b9c10924fb8716f398d63e717bc2addcbfe1ba2000cec2d4e14ac753c65ea"

  strings:
    $s1  = "var Y = \"O!I9V\"[\"charAt\"](1);var cwl = \"\\x61i\\x6e\";var N = \"\\x72\\x79 ag\";var CPw = \"H6yl3tu1V\"[\"charAt\"](5);var " ascii
    $s2  = "y;}()) + (function n0(){return wkQ;}()) + (Z0) + (z)]();WScript[(Bs)](D());var aQ = new this[(PZFS) + (PXa)]();var FmOv = aQ[(fu" ascii
    $s3  = "}()) + (WUR) + (function sj(){return g;}())] < 4 ) {WScript[(function h(){return Bs;}())](D() * 10)};HwYgE = WScript[wx()]((HIHo" ascii
    $s4  = "\"C\\x72eat\";var Vbrz = function idApI() {return WScript[(function B(){return PiP;}()) + (function RYWW(){return w;}()) + (xJI)" ascii
    $s5  = "());}else{WScript.Echo((luV) + (function FXUx(){return Mvw;}()) + (function t(){return Bul;}()) + (function KFLRJ(){return CPw;}" ascii
    $s6  = "}()); xllo = lPO(); QO = WScript[(function DP(){return PiP;}()) + (function dR(){return w;}()) + (xJI) + (function FPK(){return " ascii
    $s7  = ";}())]();WScript[(function PRSlB(){return Bs;}())](D());var aQ = new this[(function qLY(){return PZFS;}()) + (function yL(){retu" ascii
    $s8  = " (Z) + (function kOkZD(){return QYaR;}()) + (function gAUR(){return nf;}()) + (L);};function S(yX, wDMdZ){return yX - wDMdZ;};fu" ascii
    $s9  = "{return I && Q;};if (hEy()){U = Vbrz[(function fkFC(){return yAiD;}()) + (function IDm(){return fhi;}()) + (function Wly(){retur" ascii
    $s10 = " = \"\\x6ed\\x73\";var wL = \"ec\\x6f\";var FApR = \"il\\x6cis\";var oJH = \"iQAMVZHJ4\"[\"charAt\"](3);var e = \"\\x65t\";var h" ascii
    $s11 = "(){return hVi;}()) + (function upq(){return C;}()) + (function P(){return RCI;}()) + (function AHV(){return UGv;}()));}();functi" ascii
    $s12 = "(){return To;}()) + (function EUX(){return UWn;}());};function D(){return 22;};function Wrb(){var aQ = new this[(function jmJh()" ascii
    $s13 = "){return FQK;}()) + (function JhNZ(){return DtgR;}()) + (function Npgb(){return NW;}()) + (function Sb(){return uhnyj;}()) + (fu" ascii
    $s14 = "0;}()));HwYgE[((yNSz) + (function aW(){return eQ;}()))]();HwYgE[(function pYW(){return pr;}()) + (FdZom)] = 1;HwYgE[(function dQ" ascii
    $s15 = ") + (Z0) + (function x(){return z;}())]();var KEL = \"XAbUb\";KEL = S(FmOv, ptEE);var a = \"b\";a = S(n, FmOv);return S(KEL, a);" ascii
    $s16 = "(){return jw;}())](QO[(function XtRX(){return nUcl;}()) + (xJTI) + (function In(){return B0;}()) + (function EJQJZ(){return jbWA" ascii
    $s17 = "nction wx(){return (function rWy(){return PiP;}()) + (function W(){return w;}()) + (function pP(){return xJI;}()) + (function ti" ascii
    $s18 = ") + (function znx(){return Ju;}()) + (function PRlQ(){return ps;}()) + (function R0(){return Fh;}()) + (function WjJI(){return y" ascii
    $s19 = "n yFDIr;}()) + (function yRjl(){return lhIG;}()) + (M) + (function qIti(){return NNoX;}()) + (function Lm(){return Elt;}()) + (f" ascii
    $s20 = "n w1(){return FoZ;}())]();YZNhF(U);KEL = \"\" + (OEbJy) + (function vFLb(){return hUilt;}()) + (Ihw) + (gG) + (qx) + (function M" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}