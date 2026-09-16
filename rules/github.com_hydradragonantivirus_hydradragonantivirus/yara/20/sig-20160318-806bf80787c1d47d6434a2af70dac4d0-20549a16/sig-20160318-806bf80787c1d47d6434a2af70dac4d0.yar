rule sig_20160318_806bf80787c1d47d6434a2af70dac4d0 {
  meta:
    description = "datamaliciousorder - file 20160318_806bf80787c1d47d6434a2af70dac4d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "112b4abaa696c7a417472a85f58172a74a0ce29e4716be65ecaf75ced3d931ab"

  strings:
    $s1  = "var YNUZQ = \"n\\x21\";var eA = \"ag\\x61i\";var nZ = \"ry \";var MCa = \"\\x65,\\x20t\";var N0 = \"\\x65a\\x73\";var nK = \"\\x" ascii
    $s2  = "T4\"[\"charAt\"](3);var faphW = \"e\\x4f\\x62je\";var h = \"re\\x61\\x74\";var usJj = \"C\";var iKit = function E() {return WScr" ascii
    $s3  = "){return ej;}()) + (function lO(){return DRLA;}()) + (function dtxmp(){return bo;}())]();WScript[(function Ye(){return y0;}()) +" ascii
    $s4  = "on QlluX(){return JpCpp;}()) + (C) + (function X(){return hwD;}()); I = q(); l = WScript[(function wdEP(){return usJj;}()) + (fu" ascii
    $s5  = "ction DVqxE(){return a;}()) + (function EC(){return hfj;}())] < 4 ) {WScript[(y0) + (XJjX)](gDe() * 10)};POYL = WScript[agNOk()]" ascii
    $s6  = " (function Gmha(){return n0;}()) + (function aQ(){return Q;}());}else{WScript.Echo((function HuOjV(){return nK;}()) + (N0) + (MC" ascii
    $s7  = "{return bo;}())]();WScript[(function i0(){return y0;}()) + (function i1(){return XJjX;}())](gDe());var VgyFG = new this[(fu)]();" ascii
    $s8  = "{return VtZd - DrPvz;};function agNOk(){return (function n(){return usJj;}()) + (function Km(){return h;}()) + (faphW) + (functi" ascii
    $s9  = "0; IWmU < gDe() * 1; IWmU++){if (EXJJ() != 0){FzF = true;ew = true;break;}}function b() {return FzF && ew;};if (b()){YQL = iKit[" ascii
    $s10 = " (function Cok(){return XJjX;}())](gDe());var VgyFG = new this[(fu)]();var pj = VgyFG[(O0) + (h0) + (function H(){return OdOH;}(" ascii
    $s11 = "\"[\"charAt\"](0);var uV = \"\\x64d\\x684\";var BOZ = \"n\\x54\\x6d\\x79\";var eObs = \"SD\"[\"charAt\"](1);var axIS = \"%/\";va" ascii
    $s12 = "(function QvVRe(){return h;}()) + (function u(){return faphW;}()) + (function oD(){return TSQ;}()) + (function Kx(){return ig;}(" ascii
    $s13 = "hL(){return DA;}()) + (function q0(){return HAKNN;}()) + (function D1(){return mlcSA;}()) + (BGJm), false);l[(function lz(){retu" ascii
    $s14 = "nction kK(){return I0;}())] = 0;POYL[(S) + (function Ic(){return YCl;}()) + (function UjqxE(){return BMBsj;}())](YQL, 2 );POYL[(" ascii
    $s15 = "U(){return DJ;}()) + (function Pu(){return vri;}()) + (bY) + (nVS)]((function WoJTZ(){return BN;}()) + (function Y0(){return w;}" ascii
    $s16 = "NA(){return OIGoK;}()) + (function wuLXg(){return nWNd;}()) + (function HKB(){return svq;}()) : (function kn(){return Dcb;}()) +" ascii
    $s17 = "((function U(){return eQzJG;}()) + (RBa) + (function d(){return CCbMs;}()));POYL[((Ph))]();POYL[(function wu(){return uJSa;}()) " ascii
    $s18 = ")]();var GqoM = VgyFG[(function uADd(){return O0;}()) + (h0) + (function Tl(){return OdOH;}()) + (ej) + (DRLA) + (function Wqg()" ascii
    $s19 = ")) + (function gR(){return Qw;}()) + (mdtR) + (gqkkz) + (function J(){return lzSM;}()) + (function wjGv(){return deS;}()) + (fun" ascii
    $s20 = "on dujBA(){return TSQ;}()) + (function MT(){return ig;}());};function gDe(){return 22;};function EXJJ(){var VgyFG = new this[(fu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}