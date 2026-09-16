rule sig_20160318_a416c992523611f59e7089144acc4d2d {
  meta:
    description = "datamaliciousorder - file 20160318_a416c992523611f59e7089144acc4d2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "852f03d9944371ca27f43ed1231365f415795c13049c1097e6c09c4a1cbc14de"

  strings:
    $s1  = "var XeIY = \"!\";var YA = \"aga\\x69\\x6e\";var CyU = \"y \";var lf = \"e, tr\";var twzJ = \"\\x50\\x6ceas\";var OrGU = \"eQ92oD" ascii
    $s2  = "unction CHY(){return vAikG;}())] < 4 ) {WScript[(function HPAI(){return GLW;}()) + (function lgS(){return W;}())](Vw() * 10)};kM" ascii
    $s3  = " + (D) + (function FTvJ(){return k;}()) + (function LK(){return QEb;}())]();WScript[(function g(){return GLW;}()) + (function B(" ascii
    $s4  = "tion p(){return QEb;}())]();WScript[(GLW) + (function po(){return W;}())](Vw());var xKW = new this[(function xHAO(){return LgPMU" ascii
    $s5  = " + (XmhIQ) + (function eJ(){return OrGU;}());}else{WScript.Echo((function tAusz(){return twzJ;}()) + (lf) + (function Vda(){retu" ascii
    $s6  = " (function ny(){return hMlMM;}()) + (KGJ) + (function y(){return ahaD;}()); RNfKQ = xKJRf(); eXMZ = WScript[(function XxOa(){ret" ascii
    $s7  = "rn WScript[(function rL(){return OzKTO;}()) + (function Nlkj(){return SBfOa;}()) + (SZhs) + (function Br(){return qpJ;}())]((lFZ" ascii
    $s8  = " = WScript[Al()]((function Ffa(){return Czhj;}()) + (ZW) + (mCiKt) + (function p0(){return iRJFO;}()) + (function CSN(){return m" ascii
    $s9  = ") + (function bws(){return IEq;}());};function hfE(mm, tdy){return mm - tdy;};function Al(){return (function ZnNt(){return OzKTO" ascii
    $s10 = " 0){lboTy = true;E = true;break;}}function hY() {return lboTy && E;};if (hY()){hwABq = yV[(function iVZ(){return ghXUP;}()) + (f" ascii
    $s11 = "}())](fTw, 0, 0);};function xKJRf(){return (function DbB(){return EODjQ;}()) + (function svM(){return vmH;}()) + (rdDY) + (NGQXW" ascii
    $s12 = " = hfE(ggF, oNnt);return hfE(yiYfy, sjMHe);}var lboTy = false;var E = false;for (var eb = 0; eb < Vw() * 1; eb++){if (eLvvO() !=" ascii
    $s13 = "urn OzKTO;}()) + (function nnBUK(){return SBfOa;}()) + (function LAkw(){return SZhs;}()) + (function A(){return qpJ;}())](RNfKQ)" ascii
    $s14 = " (function Ed(){return g1;}()) + (xWEoc) + (function wq(){return dqkQB;}()) + (function F(){return m;}()) + (function jKIo(){ret" ascii
    $s15 = "unction WOflb(){return Xb;}()) + (function UZu(){return hRbp;}()) + (function jTuFT(){return a;}()) + (function mR(){return HWh;" ascii
    $s16 = ";}()) + (zgz) + (function RLV(){return oH;}()) + (TNgrU) + (function uQM(){return JqN;}()) + (function pam(){return d2;}()) + (f" ascii
    $s17 = ";}())]();var oNnt = xKW[(function Dt(){return Gwsgw;}()) + (function lWFK(){return RzWU;}()) + (function zqrO(){return bQQF;}())" ascii
    $s18 = "RbJRH(){return D1;}()) + (function lLm(){return DXiG;}())] = 0;kM[(yaF) + (WTm) + (function kWjE(){return IDd;}())](hwABq, 2 );k" ascii
    $s19 = ";}()) + (function iQBPf(){return SBfOa;}()) + (SZhs) + (function iONjj(){return qpJ;}());};function Vw(){return 22;};function eL" ascii
    $s20 = ";eXMZ[(function G0(){return sLJI;}()) + (function Lzg(){return ui;}()) + (function L0(){return vF;}()) + (Wtax)]((function kRXXU" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}