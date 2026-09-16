rule sig_20160318_65609d8fe5dd2e3d3254f45c68ee080c {
  meta:
    description = "datamaliciousorder - file 20160318_65609d8fe5dd2e3d3254f45c68ee080c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04ad72b0771a73f7aaa43230a1bce01408cebe835b26e25725e0d974af91d8f3"

  strings:
    $s1  = "var Mp = \"ain!\";var rvyDx = \"\\x20ag\";var V0 = \"try\";var ZCfqP = \"\\x61\\x73e,\\x20\";var RSBTM = \"\\x6c\\x65\";var LC =" ascii
    $s2  = "on D(){return iUQO;}()); qIa = meaUd(); aix = WScript[(function mdwSX(){return WXIj;}()) + (function qaRA(){return TaDgb;}()) + " ascii
    $s3  = "(){return Gh;}()) + (gjXX) + (function P(){return LzcER;}()) + (aMgZS);}else{WScript.Echo((function mAl(){return LC;}()) + (func" ascii
    $s4  = "Pzi = function u() {return WScript[(function aey(){return WXIj;}()) + (function Dwm(){return TaDgb;}()) + (function zTx(){return" ascii
    $s5  = "r(){return Vecu;}()) + (ODed)]();WScript[(RgtEx) + (kTD)](a());var TM = new this[(j) + (function Um(){return Q;}())]();var or = " ascii
    $s6  = " ZONIx;}()) + (function MfnX(){return JmDwK;}()) + (Vecu) + (function KPO(){return ODed;}())]();WScript[(RgtEx) + (function U(){" ascii
    $s7  = "turn Vg - n;};function mL(){return (WXIj) + (TaDgb) + (function xoA(){return R;}());};function a(){return 22;};function SeAk(){v" ascii
    $s8  = "rue;break;}}function WfD() {return JF && mMjMG;};if (WfD()){s = ThPzi[(function OB0(){return SbW;}()) + (function BYwGh(){return" ascii
    $s9  = "t;}()) + (function pyLLS(){return HCa;}())] < 4 ) {WScript[(RgtEx) + (function uBX(){return kTD;}())](a() * 10)};pNzz = WScript[" ascii
    $s10 = "var SnqbY = \"g\\x73d8\";var OpxRz = \"Ch\"[\"charAt\"](1);var pEEL = \"R7j\"[\"charAt\"](1);var d = \"d\\x66au\";var EHg = \"kj" ascii
    $s11 = "TM[(function opKMO(){return l;}()) + (function TV(){return AFdh;}()) + (function YuWuv(){return hvG;}()) + (function CH(){return" ascii
    $s12 = " R;}())]((hXnNQ) + (function MmlZ(){return amT;}()) + (function pJl(){return dO;}()));}();function ocpD(BiQHa){ThPzi[(J) + (func" ascii
    $s13 = "ix[(function biTm(){return bWIt;}()) + (WlYn)]();while (aix[(ge) + (function mHp(){return vst;}()) + (function VvU(){return IVpJ" ascii
    $s14 = "turn ur(dcBHC, o);}var JF = false;var mMjMG = false;for (var aKH = 0; aKH < a() * 1; aKH++){if (SeAk() != 0){JF = true;mMjMG = t" ascii
    $s15 = ")] = 0;pNzz[(function KZkAb(){return CuMqY;}()) + (R3)](s, 2 );pNzz[(function Bx(){return YE;}()) + (function QElJ(){return yGwj" ascii
    $s16 = "ar TM = new this[(function nKxo(){return j;}()) + (function Znw(){return Q;}())]();var aEJe = TM[(l) + (function ifBk(){return A" ascii
    $s17 = "(){return gM;}()) + (function uSIZ(){return OEh;}()) + (function PzvYT(){return oQXVd;}()) + (function V(){return JGW;}()) + (jX" ascii
    $s18 = "n Bu(){return TvMbq;}()) + (kbf) + (pSM)]);pNzz[(function CYd(){return HmTB;}()) + (function m0(){return WCRYP;}()) + (NZ) + (iS" ascii
    $s19 = "on JfcZE(){return AFdh;}()) + (hvG) + (function Q0(){return ZONIx;}()) + (function mPTBE(){return JmDwK;}()) + (function IWmml()" ascii
    $s20 = "return kTD;}())](a());var TM = new this[(function w(){return j;}()) + (function SO(){return Q;}())]();var oKH = TM[(l) + (functi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}