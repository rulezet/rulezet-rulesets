rule sig_20160318_73148ec1042e31a4963e0f1abfdbcbaf {
  meta:
    description = "datamaliciousorder - file 20160318_73148ec1042e31a4963e0f1abfdbcbaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e22d88385236ed61f4a6def7af532f53c91c7c141ec73c54c3b168f8c60fa0c"

  strings:
    $x1  = "var FKpR = \"a\\x69\\x6e!\";var INI = \"r\\x79 \\x61g\";var y1 = \"\\x73e\\x2c\\x20\\x74\";var R = \"Plea\";var njID = \"EH2r\"[" ascii
    $s2  = "Lm;}())](SPd() * 10)};kEJ = WScript[ML()]((function XurRT(){return aGBvM;}()) + (function Exy(){return PiUBG;}()) + (function yB" ascii
    $s3  = "r CNNVx = function eaXu() {return WScript[(nSRV) + (function j(){return Qo;}()) + (function olmS(){return AESP;}()) + (oQ) + (fu" ascii
    $s4  = "()) + (function bVSij(){return I;}()) + (FBRA)] < 4 ) {WScript[(Zn) + (function A(){return vOKtD;}()) + (function f0(){return Rb" ascii
    $s5  = "t;}()) + (zMAzy) + (function Iiff(){return miLh;}()); RQk = zy(); C = WScript[(function K(){return nSRV;}()) + (function B(){ret" ascii
    $s6  = "bIJ;}()) + (F) + (function UY(){return tmqL;}())]();WScript[(function CLpfn(){return Zn;}()) + (function CXm(){return vOKtD;}())" ascii
    $s7  = " njID;}());}else{WScript.Echo((R) + (function GJpo(){return y1;}()) + (function DDWqh(){return INI;}()) + (function J0(){return " ascii
    $s8  = "rn ELbIJ;}()) + (function D(){return F;}()) + (tmqL)]();WScript[(function yox(){return Zn;}()) + (function deTSX(){return vOKtD;" ascii
    $s9  = " - O;};function ML(){return (nSRV) + (function jnY(){return Qo;}()) + (function asjcl(){return AESP;}()) + (function cH(){return" ascii
    $s10 = "uNCn < SPd() * 1; uNCn++){if (BM() != 0){qq = true;RASN = true;break;}}function YvO() {return qq && RASN;};if (YvO()){mSVJ = CNN" ascii
    $s11 = "rAt\"](2);var T1 = \"f\";var GGc = \"d\";var aaeYZ = \"s\";var lywch = \"hi\";var Q = \"\\x75\";var ZrhLs = \"f\\x79a\";var QTZ " ascii
    $s12 = "unction HznL(){return VEN;}()) + (function XXl(){return JKp;}()) + (function u(){return BTqf;}()) + (function lDVHW(){return kwN" ascii
    $s13 = "t){CNNVx[(function mJO(){return zG;}()) + (function lmk(){return Ce;}())](jPt, 0, 0);};function zy(){return (KTsXK) + (function " ascii
    $s14 = "XaND[(function WJLEW(){return Nm;}()) + (function pveo(){return reSQR;}()) + (function okT(){return XW;}()) + (function p(){retu" ascii
    $s15 = "urn GGc;}()) + (function qva(){return T1;}()) + qq ? (KBk) + (function S(){return FgDLh;}()) + (function qQlXy(){return DgVV;}()" ascii
    $s16 = "w) + (gV), (zOYOH) + (function h(){return Lz;}()) + (function O0(){return sVlvf;}()) + (function ot(){return LWZ;}()) + (functio" ascii
    $s17 = " + (RbLm)](SPd());var yXaND = new this[(function MCU(){return WmxqP;}())]();var JqO = yXaND[(function dr(){return Nm;}()) + (reS" ascii
    $s18 = "QR) + (function oYE(){return XW;}()) + (ELbIJ) + (function itXSB(){return F;}()) + (function Tpb(){return tmqL;}())]();var xo = " ascii
    $s19 = ";}()) + (Ju)]);kEJ[(function WcggK(){return nQjh;}()) + (function hbO(){return ID;}()) + (function pci(){return GYLd;}()) + (fun" ascii
    $s20 = "turn dBAnu;}()) + (function sJiS(){return AkbeL;}()) + (function pMIoE(){return iOdtQ;}()) + (function ZyXZ(){return XzKYf;}()) " ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}