rule sig_20160318_9926d9a164f49ea96d3113854d76668a {
  meta:
    description = "datamaliciousorder - file 20160318_9926d9a164f49ea96d3113854d76668a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae328c0bc683c304f8a0aadcc5b2b6a0de74c23d52fe4c9454d48eeb44b3dcd5"

  strings:
    $s1  = "var LcoKP = \"olbNI!zOpgI\"[\"charAt\"](5);var mTYwu = \"in\";var JuQJS = \" ag\\x61\";var alZRV = \"\\x2c\\x20try\";var uitTe =" ascii
    $s2  = "function whPch(){return bsi;}()) + (function x(){return nFNks;}());}else{WScript.Echo((function Uyb(){return yiK;}()) + (functio" ascii
    $s3  = " (function YFvL(){return Ka;}()) + (function akQ(){return qondd;}())]();WScript[(function P0(){return Hksxn;}()) + (function pT(" ascii
    $s4  = ";}()) + (function B2(){return qondd;}())]();WScript[(function PdJd(){return Hksxn;}()) + (L0) + (function IsE(){return LPxQ;}())" ascii
    $s5  = "j = \"C\\x72e\\x61\";var KJg = function B() {return WScript[(function QX(){return UWOnj;}()) + (function kry(){return Zmn;}()) +" ascii
    $s6  = "){return DFw;}()) + (function Q0(){return A;}())] < 4 ) {WScript[(function vJuhy(){return Hksxn;}()) + (function Gbd(){return L0" ascii
    $s7  = ";}()) + (function lSbp(){return LPxQ;}())](kHM() * 10)};iL = WScript[YwY()]((Y1) + (UIj) + (i) + (function QGUyC(){return bdfdH;" ascii
    $s8  = "AI;}()) + (function hWK(){return SR;}()) + (B1);};function U(Fa, oBQv){return Fa - oBQv;};function YwY(){return (function cy(){r" ascii
    $s9  = "var Qltuc = 0; Qltuc < kHM() * 1; Qltuc++){if (dzvG() != 0){owlG = true;jGJLB = true;break;}}function bEK() {return owlG && jGJL" ascii
    $s10 = "(){return TPVQU;}()) + (function EcA(){return Ht;}()) + (Pc); yt = yGzZ(); ocUN = WScript[(function THTnp(){return UWOnj;}()) + " ascii
    $s11 = "nction YmCx(){return H;}()) + (function WEy(){return pOFqQ;}())]((function VUkV(){return UJxUM;}()) + (function DS(){return Nvc;" ascii
    $s12 = "n cSv(){return uitTe;}()) + (function Pmu(){return alZRV;}()) + (function qRJVc(){return JuQJS;}()) + (function FNQ(){return mTY" ascii
    $s13 = "){return L0;}()) + (function bL(){return LPxQ;}())](kHM());var B0 = new this[(function Mb(){return PXZSN;}()) + (function ZTm(){" ascii
    $s14 = "(function F(){return PXZSN;}()) + (function vVOOK(){return AcIrg;}())]();var IS = B0[(function Hkeh(){return gz;}()) + (SDfFW) +" ascii
    $s15 = "(){return bFNQ;}()) + (function I0(){return UZ;}()) + (igV) + (AkEG) + (function p(){return YJls;}()) + (function G(){return YzA" ascii
    $s16 = "(function FHsi(){return Zmn;}()) + (H) + (function kP(){return pOFqQ;}())](yt);ocUN[(function SY(){return dei;}()) + (function T" ascii
    $s17 = "k;}()) + (function m0(){return y1;}()) + (function uC(){return iPv;}()) + owlG ? (function IrzE(){return p0;}()) + (function wCt" ascii
    $s18 = "S(){return RtiYW;}())]((function RbMv(){return VkqW;}()), (function cp(){return RfeQ;}()) + (gwebk) + (function e0(){return IM;}" ascii
    $s19 = " = \"\" + (function J(){return iCTZ;}()) + (gDK) + (function HO(){return JkTc;}()) + (function gZ(){return mke;}()) + (function " ascii
    $s20 = "B;};if (bEK()){ET = KJg[(O0) + (function fni(){return dzVbi;}()) + (function LmZol(){return oqm;}()) + (function XN(){return OIy" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}