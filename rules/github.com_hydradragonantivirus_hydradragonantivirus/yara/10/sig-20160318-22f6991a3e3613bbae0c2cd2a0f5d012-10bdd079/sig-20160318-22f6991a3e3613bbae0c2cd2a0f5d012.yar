rule sig_20160318_22f6991a3e3613bbae0c2cd2a0f5d012 {
  meta:
    description = "datamaliciousorder - file 20160318_22f6991a3e3613bbae0c2cd2a0f5d012.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f551e382aed4cd4dec1b6c9c27c51b8f8a1a85aa15021a5f944f9339d92cde40"

  strings:
    $x1  = "var iznJ = \"n!\";var tCy = \"ga\\x69\";var wdoiu = \"y\\x20\\x61\";var CXHDT = \"\\x65, tr\";var vuDB = \"Pl\\x65as\";var DVeyg" ascii
    $s2  = "sFQc;}())] < 4 ) {WScript[(JA)](Jra() * 10)};icuq = WScript[GenbZ()]((B) + (D) + (function hGDAH(){return gUtu;}()) + (f0));icuq" ascii
    $s3  = "Zs) + (function UdHbx(){return DVeyg;}());}else{WScript.Echo((function Fhk(){return vuDB;}()) + (CXHDT) + (function rw(){return " ascii
    $s4  = "(WLfu); T = LgYZE(); X = WScript[(function LADLG(){return uKTd;}()) + (FaqI) + (function N0(){return ZZ;}()) + (function TVap(){" ascii
    $s5  = "n F;}()) + (function VeR(){return Emf;}()) + (function TCxk(){return KWQx;}())]();WScript[(function v0(){return JA;}())](Jra());" ascii
    $s6  = " + (kGLQC) + (b) + (function iQD(){return F;}()) + (function UUc(){return Emf;}()) + (function m(){return KWQx;}())]();WScript[(" ascii
    $s7  = "\";var FaqI = \"\\x74eO\";var uKTd = \"C\\x72e\\x61\";var FX = function tsa() {return WScript[(function sLZ(){return uKTd;}()) +" ascii
    $s8  = "Ub(DCGSD, M){return DCGSD - M;};function GenbZ(){return (function jUZ(){return uKTd;}()) + (function G(){return FaqI;}()) + (fun" ascii
    $s9  = "e;nv = true;break;}}function VGIE() {return AaF && nv;};if (VGIE()){nNbbi = FX[(j2) + (function Woe(){return fKxY;}()) + (functi" ascii
    $s10 = "ction JiEks(){return ZZ;}()) + (function j0(){return ulZf;}());};function Jra(){return 22;};function AWDk(){var qlwF = new this[" ascii
    $s11 = "on jo(){return zEHt;}()) + (function DmYW(){return cLUMn;}()) + (Oqq) + (vGZFJ) + (function Smw(){return qq;}()) + (eVDP) + (fun" ascii
    $s12 = "()) + (function X0(){return r;}())] = 0;icuq[(function GGtM(){return TeWL;}()) + (function ZeIT(){return nkf;}()) + (function gx" ascii
    $s13 = " S(){return aQb;}()) : (function ro(){return OkBCO;}()) + (function P(){return LYGtl;}()) + (function bzw(){return ec;}()) + (Th" ascii
    $s14 = "+ (function TyDH(){return ZZ;}()) + (ulZf)]((nzckG) + (function nOCTK(){return KrYCV;}()) + (function Dx(){return fcuz;}()) + (f" ascii
    $s15 = "[((function h(){return OSI;}()))]();icuq[(function GYPwo(){return GEqzf;}())] = 1;icuq[(function BhvQU(){return dUdIo;}()) + (fu" ascii
    $s16 = "E(){return (function qV(){return N1;}()) + (function pexj(){return kJTu;}()) + (ULB) + (function Of(){return y;}());};function z" ascii
    $s17 = "lR(){return oMPnd;}()) + (TOfv) + (EVD) + AaF ? (function TPDBp(){return nXn;}()) + (function pZ(){return hGOsq;}()) + (function" ascii
    $s18 = "rn sYEpi;}()) + (function v(){return WWzi;}()) + (function IV(){return kGLQC;}()) + (b) + (function RGKZ(){return F;}()) + (func" ascii
    $s19 = "tion k(){return sYEpi;}()) + (WWzi) + (function ryBmA(){return kGLQC;}()) + (function RE(){return b;}()) + (function xpD(){retur" ascii
    $s20 = "ion T1(){return eHp;}()) + (function EJQ(){return UHvy;}()) + (function t(){return dsv;}()) + (function lgGT(){return ZpHxe;}())" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}