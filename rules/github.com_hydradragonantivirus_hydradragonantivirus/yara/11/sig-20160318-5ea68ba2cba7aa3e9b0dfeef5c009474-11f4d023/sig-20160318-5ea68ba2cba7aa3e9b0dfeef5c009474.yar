rule sig_20160318_5ea68ba2cba7aa3e9b0dfeef5c009474 {
  meta:
    description = "datamaliciousorder - file 20160318_5ea68ba2cba7aa3e9b0dfeef5c009474.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b697b0c319f7895cf807bf5da35cdabb88483f08b41d92b3b50b7c79c1510b7"

  strings:
    $x1  = "var YRI = \"i\\x6e\\x21\";var JKNaf = \"y\\x20\\x61ga\";var L0 = \"e\\x2c \\x74\\x72\";var tfFT = \"Pl\\x65\\x61s\";var zIS = \"" ascii
    $s2  = "ew this[(function rtEmp(){return EeeYp;}())]();var el = IcLH[(function Smd(){return h;}()) + (cD) + (function PL(){return gqJ;}(" ascii
    $s3  = " g1(){return zIS;}());}else{WScript.Echo((function hd(){return tfFT;}()) + (L0) + (function ctxb(){return JKNaf;}()) + (function" ascii
    $s4  = "ion CULjo(){return M;}())] < 4 ) {WScript[(function gqJlZ(){return ZP;}())](mOno() * 10)};hidx = WScript[vNG()]((function yGm(){" ascii
    $s5  = "unction J(){return gqJ;}()) + (HYz) + (function lR(){return S;}())]();WScript[(function N(){return ZP;}())](mOno());var IcLH = n" ascii
    $s6  = "return zS;}()) + (function HoVOZ(){return o0;}()) + (function brR(){return KNh;}()); T = DLyv(); otd = WScript[(function rt(){re" ascii
    $s7  = "return cD;}()) + (function E(){return gqJ;}()) + (function CQOX(){return HYz;}()) + (function GIPx(){return S;}())]();WScript[(f" ascii
    $s8  = "ction ucWV(ViSt, Vot){return ViSt - Vot;};function vNG(){return (function lPate(){return mx;}()) + (Ejyd) + (function niY(){retu" ascii
    $s9  = "P() {return asq && hUHV;};if (eKeP()){y = Ns[(function mClP(){return V;}()) + (function OSjH(){return V0;}()) + (Wayri) + (funct" ascii
    $s10 = " dTv = \"\\x57\";var sMk = \"e\\x63t\";var Ejyd = \"teObj\";var mx = \"Cr\\x65\\x61\";var Ns = function FmUsB() {return WScript[" ascii
    $s11 = "nction foZ(){return Fk;}()) + (function mhNqH(){return CsmC;}())] = 1;hidx[(function MA(){return bi;}()) + (function iKRz(){retu" ascii
    $s12 = "ion aMXOi(){return AIq;}()) + (LyG) + (function ofE(){return PP;}()) + (function sSbbr(){return L;}()) + (function F(){return RR" ascii
    $s13 = "tion jI(){return Bsn;}())](y, 2 );hidx[(NXQ) + (function iZrWK(){return Zxg;}()) + (eNVi)]();aB(y);k = \"\" + (function nJVi(){r" ascii
    $s14 = "rn sMk;}());};function mOno(){return 22;};function jxWPk(){var IcLH = new this[(EeeYp)]();var bbe = IcLH[(h) + (function ITEp(){" ascii
    $s15 = "ezgA(){return kz;}()) + (function fucu(){return g;}()) + (i) + (function Ow(){return PsH;}()) + (function xl(){return c;}()) + (" ascii
    $s16 = "(){return BPN;}()) + (function g0(){return Fhmeh;}()) + (function VVJue(){return AH;}()) + (function CY(){return YPr;}()) + (fun" ascii
    $s17 = "unction I(){return xnls;}())]();while (otd[(function eOrVj(){return bF;}()) + (function grbKw(){return o1;}()) + (tHut) + (funct" ascii
    $s18 = "rn qX;}())](otd[(X) + (KXc) + (function EfT(){return ltEd;}()) + (function KK(){return a;}())]);hidx[(function r0(){return stEfS" ascii
    $s19 = "function Hr(){return KoR;}()) + (function HMGGw(){return cntdv;}()) + (mto) + (function oEs(){return hSJ;}()) + (function cZ(){r" ascii
    $s20 = "nQ;}()) + (function RcQeH(){return fnLg;}()) : (function NMjlU(){return c0;}()) + (function AUFXZ(){return mEAb;}()) + (function" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}