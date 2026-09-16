rule sig_20160318_14670e819662f3bf3940d83546de8f0f {
  meta:
    description = "datamaliciousorder - file 20160318_14670e819662f3bf3940d83546de8f0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c76798ca731c6ff70728f57087c89c75d60887e15613d352f51b0c07f27d891"

  strings:
    $s1  = "var Sbqq = \"ain!\";var f = \" \\x61\\x67\";var ZOoj = \"try\";var zXdkw = \" \";var V1 = \"\\x65\\x2c\";var ZoDE = \"\\x50\\x6c" ascii
    $s2  = ");var mQJ = \"COaH3d\"[\"charAt\"](0);var HGx = function YIQqZ() {return WScript[(function tn(){return mQJ;}()) + (function rjiv" ascii
    $s3  = " rGPBA(){return V0;}()) + (s)] < 4 ) {WScript[(EOPa) + (function VKPIV(){return tR;}())](aOhK() * 10)};C = WScript[chjr()]((func" ascii
    $s4  = "urn mWi;}()) + (function VgVX(){return qVYeO;}()) + (function fe(){return GB;}()); om = MxA(); EuvCj = WScript[(function TXT(){r" ascii
    $s5  = "n u;}()) + (function hd(){return ZcF;}())]();WScript[(EOPa) + (function rC(){return tR;}())](aOhK());var R = new this[(function " ascii
    $s6  = "rn Ruwe;}()) + (function Df(){return u;}()) + (function qwJcI(){return ZcF;}())]();WScript[(function PAP(){return EOPa;}()) + (t" ascii
    $s7  = "unction JDiXi(){return stcNw;}()) + (Tty) + (XxX);}else{WScript.Echo((function aLm(){return ZoDE;}()) + (function Su(){return V1" ascii
    $s8  = "h(EIKy, Bbo){return EIKy - Bbo;};function chjr(){return (function B(){return mQJ;}()) + (hLZy) + (function VF(){return ooWe;}())" ascii
    $s9  = "tion k(){return uNZe;}()) + (function dM(){return JEPmC;}())]();FlEr(Q);LkQa = \"\" + (function BinK(){return Ejmt;}()) + (funct" ascii
    $s10 = " o0 = \"dfau\";var a = \"aos\";var haxl = \"lf\\x6bj\";var Ejmt = \"\\x61sd\";var JEPmC = \"se\";var uNZe = \"lo\";var lp = \"cf" ascii
    $s11 = "){return Eg;}()) + (function AU(){return P;}()) + dIRPS ? (function Y1(){return ZRa;}()) + (function xld(){return kqHn;}()) : (f" ascii
    $s12 = "f;}()) + (function xhl(){return TCHFT;}()) + (function pMsNL(){return Zh;}()) + (function Y0(){return ve;}()) + (function rnyYv(" ascii
    $s13 = " + (function m(){return mVcZ;}()) + (function I(){return Ux;}());};function aOhK(){return 22;};function wpZTk(){var R = new this" ascii
    $s14 = "(function xSe(){return myan;}())]();while (EuvCj[(function jbSI(){return Jfcsr;}()) + (function T(){return vpYc;}()) + (function" ascii
    $s15 = "tion QQwa(){return o;}()) + (uaIH) + (YqgFR) + (juBX) + (WxE));C[((function VNx(){return y;}()))]();C[(function bcycg(){return K" ascii
    $s16 = "fOQ(){return fE;}()) + (fqS) + (function hEDH(){return BN;}()) + (Td) + (function tXVSk(){return JOU;}()) + (function D(){return" ascii
    $s17 = "[(function DZip(){return iJoqc;}())]();var tCEzX = R[(wlb) + (function anHVK(){return bIR;}()) + (Ruwe) + (function lqYE(){retur" ascii
    $s18 = "eturn mQJ;}()) + (hLZy) + (function waio(){return ooWe;}()) + (function EL(){return mVcZ;}()) + (function Z(){return Ux;}())](om" ascii
    $s19 = ";krqZN = AcvDh(Scgs, Fl);return AcvDh(LkQa, krqZN);}var dIRPS = false;var armCG = false;for (var QGTgn = 0; QGTgn < aOhK() * 1; " ascii
    $s20 = ");EuvCj[(function ok(){return y;}())]((function K(){return JeM;}()) + (function Ik(){return wE;}()), (function TrazA(){return vn" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}