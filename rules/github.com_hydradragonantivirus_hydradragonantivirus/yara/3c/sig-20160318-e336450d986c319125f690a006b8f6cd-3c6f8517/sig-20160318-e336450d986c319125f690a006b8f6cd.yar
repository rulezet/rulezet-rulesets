rule sig_20160318_e336450d986c319125f690a006b8f6cd {
  meta:
    description = "datamaliciousorder - file 20160318_e336450d986c319125f690a006b8f6cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1888ded6176fb0198dc03360b30fc3476be15ebe7ce9c1fc4d23770019cc8b91"

  strings:
    $s1  = "var Tewe = \"n!\";var pr = \"\\x61g\\x61i\";var bMPkf = \"r\\x79\\x20\";var Sjh = \"e, t\";var W0 = \"rWsvHJ\"[\"charAt\"](2);va" ascii
    $s2  = "function SCvm(){return yfD;}()) + (function UR(){return rXpA;}()) + (function DYJ(){return ig;}()) + (OvmGn) + (Ju)]();WScript[(" ascii
    $s3  = "(function z(){return bBQ;}()) + (RLm)](gl() * 10)};lmXd = WScript[pqnz()]((function dISQ(){return FVC;}()) + (function aBTJ(){re" ascii
    $s4  = "74e\";var GDfYF = \"C\";var NocI = function O() {return WScript[(GDfYF) + (function f(){return QQ;}()) + (function MZwtU(){retur" ascii
    $s5  = "()) + (function wsaL(){return Ju;}())]();WScript[(function o1(){return UNv;}()) + (function qRMg(){return bBQ;}()) + (function e" ascii
    $s6  = "(function j(){return mJcIM;}());}else{WScript.Echo((Mrj) + (function EJH(){return kFLPI;}()) + (function FiZk(){return HYBN;}())" ascii
    $s7  = "nn;}()) + (function gcC(){return om;}()) + (function WuMOT(){return wPc;}())] < 4 ) {WScript[(function cDQb(){return UNv;}()) + " ascii
    $s8  = "+ (function WizlI(){return cp;}()) + (xTK) + (jwQ) + (function jhql(){return WoXm;}()) + (rp); u = ZzGLT(); J = WScript[(functio" ascii
    $s9  = "rn y - ssSm;};function pqnz(){return (function TQH(){return GDfYF;}()) + (function eBuD(){return QQ;}()) + (function PBeS(){retu" ascii
    $s10 = "tion YXmPG() {return hajfq && Od;};if (YXmPG()){yA = NocI[(function DEp(){return Jcok;}()) + (XNoyD) + (function e1(){return OC;" ascii
    $s11 = ")) + (function y2(){return eS;}()) + (function NYjh(){return ZMc;}()) + hajfq ? (function WWNKZ(){return PF;}()) + (function AAl" ascii
    $s12 = "()) + (function kIhE(){return qqw;}()) + (function Hos(){return tKu;}()) + (bAdj) + (Bkc) + (function Ruo(){return yuWIs;}()) + " ascii
    $s13 = "rn pr;}()) + (function xc(){return Tewe;}()));}" fullword ascii
    $s14 = ";}()), false);J[(y0)]();while (J[(function eQ(){return bWYRX;}()) + (function TnA(){return dU;}()) + (function tGHw(){return GlY" ascii
    $s15 = " + (function E0(){return W0;}()) + (function INRXH(){return Sjh;}()) + (function TtRzN(){return bMPkf;}()) + (function GP(){retu" ascii
    $s16 = "unction o0(){return yfD;}()) + (function GjB(){return rXpA;}()) + (function Ps(){return ig;}()) + (function KYH(){return OvmGn;}" ascii
    $s17 = "H);}var hajfq = false;var Od = false;for (var dXR = 0; dXR < gl() * 1; dXR++){if (bL() != 0){hajfq = true;Od = true;break;}}func" ascii
    $s18 = "function Ep(){return UNv;}()) + (function iVt(){return bBQ;}()) + (function sbqiQ(){return RLm;}())](gl());var qiWJ = new this[(" ascii
    $s19 = "turn Tzh;}()) + (function cZI(){return f1;}()));lmXd[((function pH(){return OPVQZ;}()) + (function ycK(){return STdM;}()))]();lm" ascii
    $s20 = "(function JDM(){return Dh;}()) + (function SY(){return iZP;}()) + (function kGOzF(){return zQ;}()) + (function Ftyh(){return oAn" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}