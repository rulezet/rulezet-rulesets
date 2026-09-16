rule sig_20160318_cc8bf19b014893b948438044a7516342 {
  meta:
    description = "datamaliciousorder - file 20160318_cc8bf19b014893b948438044a7516342.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbee59d154bb901f72b9efa376c92c8cb02d6477171e2be69e121868da77c93d"

  strings:
    $s1  = "var vFU = \"\\x6e!\";var TPM = \"ag\\x61\\x69\";var sasR = \"try \";var Ys = \"\\x65, \";var xPef = \"l\\x65as\";var wajc = \"YZ" ascii
    $s2  = "()) + (function Cx(){return MlXT;}()) + (function Kgfd(){return Lcdt;}())](qnsBj() * 10)};IrMPf = WScript[q()]((gDS) + (function" ascii
    $s3  = "0(){return Bo;}()) + (Evf) + (NWu) + (function Eqcx(){return o;}())]();WScript[(function LC(){return eoR;}()) + (function kmb(){" ascii
    $s4  = "}());}else{WScript.Echo((function VUZ(){return wajc;}()) + (xPef) + (function WK(){return Ys;}()) + (function npqj(){return sasR" ascii
    $s5  = "(){return cIEyQ;}()) + (function divL(){return OZQ;}()) + (function X(){return s;}())] < 4 ) {WScript[(function J(){return eoR;}" ascii
    $s6  = "n = \"Cr\\x65\";var grJy = function h() {return WScript[(function ag(){return PnPgn;}()) + (function iGz(){return I;}()) + (h0)]" ascii
    $s7  = " (function rEi(){return o;}())]();WScript[(function oCocd(){return eoR;}()) + (function lAEDw(){return MlXT;}()) + (Lcdt)](qnsBj" ascii
    $s8  = "unction c0(){return BPwOd;}()) + (function bV(){return C;}()); zGBr = VFK(); xq = WScript[(function Hc(){return PnPgn;}()) + (fu" ascii
    $s9  = "nction Z(R, vhHF){return R - vhHF;};function q(){return (function yH(){return PnPgn;}()) + (function vQAUl(){return I;}()) + (h0" ascii
    $s10 = "{return FBGs && G;};if (slrb()){m = grJy[(function hyPB(){return dQrG;}()) + (k) + (cvTWI) + (function DGt(){return aR;}()) + (f" ascii
    $s11 = "\"\\x6fpen\";var f = \"m\";var rZnP = \"re\\x61\";var beuih = \"rUt0tSYkrW\"[\"charAt\"](4);var pkyO = \"DB.\\x53\";var YOliY = " ascii
    $s12 = "rn OmAC;}()) + (function R1(){return lArn;}()) + (function XVvH(){return MAaI;}()) + (VjCnT) + (function Um(){return ecp;}()) + " ascii
    $s13 = "turn ARUQ;}()) + (function Xx(){return xqr;}()) + (function hkC(){return JabMQ;}()) + (function mF(){return s0;}()) + (function " ascii
    $s14 = ";}()) + (function huJz(){return TPM;}()) + (vFU));}" fullword ascii
    $s15 = "Ry(){return hOsSR;}()) + (function m0(){return PzROq;}()) + (function t(){return msYZ;}()) + (function Jh(){return KsD;}());};fu" ascii
    $s16 = "nction g(){return I;}()) + (function hEEd(){return h0;}())](zGBr);xq[(function vLeV(){return tRwZU;}()) + (function WIz(){return" ascii
    $s17 = "MdIu(){return Zyo;}()) + (function ZINHz(){return NvSFW;}()) + (function Vd(){return olef;}()) + (function KHo(){return LYTVH;}(" ascii
    $s18 = "(VQm) + (dMH), false);xq[(function jEdki(){return ESGH;}()) + (function u(){return nDIf;}())]();while (xq[(R2) + (function Uwfhs" ascii
    $s19 = "T(){return bajKP;}()) + (function Oj(){return lwCio;}()) : (function PEC(){return dglo;}()) + (MPGI) + (function qX(){return t0;" ascii
    $s20 = "UD) + (function i(){return hFgW;}()) + (function YmV(){return MGz;}()) + (function kOi(){return xj;}()));}();function ICu(qOxd){" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}