rule sig_20160318_4fb67b4e0f6e885cc85c64041425a26e {
  meta:
    description = "datamaliciousorder - file 20160318_4fb67b4e0f6e885cc85c64041425a26e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9f51b2d7cc69f26cafac8c5003b4d942adf4d22aa122a54ef95ba2fda6c09bb"

  strings:
    $s1  = "var t = \"n!\";var Jjfgd = \"\\x67\\x61\\x69\";var ANDM = \"try a\";var JIz = \"ase,\\x20\";var YRF = \"P\\x6c\\x65\";var gqbf =" ascii
    $s2  = "unction sO(){return ZFa;}()) + (function uRGFS(){return gqbf;}());}else{WScript.Echo((function tzjk(){return YRF;}()) + (JIz) + " ascii
    $s3  = "ction kDg(){return gu;}()) + (eMU) + (function Uvf(){return zO;}()) + (function s(){return RocGW;}())]();WScript[(function UQmJ(" ascii
    $s4  = " (function oXPB(){return pOu;}())](zMZM() * 10)};id = WScript[xntYP()]((function LWM(){return ZV;}()) + (function nTMjc(){return" ascii
    $s5  = "5O\";var oL = \"\\x43\\x72\";var pzwm = function vEm() {return WScript[(function lM(){return oL;}()) + (function tf(){return qut" ascii
    $s6  = "z) + (function AKj(){return gsnfL;}()) + (function e(){return l;}()); G = tHvhv(); Cs = WScript[(oL) + (function SPx(){return qu" ascii
    $s7  = ";function oND(CVRN, kL){return CVRN - kL;};function xntYP(){return (function MlsQZ(){return oL;}()) + (function OvsWR(){return q" ascii
    $s8  = " vKPjC < zMZM() * 1; vKPjC++){if (qC() != 0){I = true;F = true;break;}}function ouN() {return I && F;};if (ouN()){od = pzwm[(fun" ascii
    $s9  = ")) + (tb) + (function KIit(){return fwAUn;}()) + (function hGOw(){return Lb;}())] < 4 ) {WScript[(function a(){return Bca;}()) +" ascii
    $s10 = "nction gZxn(){return NEtC;}()) + (function PYd(){return jiOS;}()) + (BgKxU) + (function nRWa(){return C;}()));}();function pj(Ms" ascii
    $s11 = "Qg = lDLE[(gu) + (function mhCB(){return eMU;}()) + (function EL(){return zO;}()) + (function zQaoE(){return RocGW;}())]();WScri" ascii
    $s12 = " MIL;}()) + (function OjkAS(){return B;}()) + (function qO(){return sRrIx;}()));id[((function y0(){return J0;}()) + (function Fm" ascii
    $s13 = "(function VJe(){return ANDM;}()) + (Jjfgd) + (function xszp(){return t;}()));}" fullword ascii
    $s14 = "]((function vEbLn(){return mR;}()) + (function jHP(){return MCT;}()), (VGhNj) + (function coGaP(){return kw;}()) + (SvsK) + (fun" ascii
    $s15 = "ction sq(){return jXa;}()) + (function kPMjt(){return VSwga;}()) + (function tuwod(){return KhF;}()) + (jrMg) + (function BBVo()" ascii
    $s16 = "){pzwm[(function fXbq(){return T;}()) + (function Pub(){return qhL;}())](Ms, 0, 0);};function tHvhv(){return (function H(){retur" ascii
    $s17 = ";}())]((function KFDp(){return YMvn;}()) + (OmOe) + (function J(){return liV;}())) + (oJg) + (function cH(){return z;}()) + (YSW" ascii
    $s18 = "on T0(){return OH;}()) + (function soV(){return Yd;}()) + (function jLfGr(){return pClNH;}()) + (function zAcU(){return DYrgU;}(" ascii
    $s19 = "n u;}()) + (udZ) + (function VchoI(){return YS;}()) + (function FCj(){return tAe;}()) + (function Zpp(){return DwLH;}()) + (M);}" ascii
    $s20 = "{return gY;}()) + (function IfCtp(){return M0;}()) + (function iwj(){return W;}()) + (function KNrHT(){return ZUo;}()) + (functi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}