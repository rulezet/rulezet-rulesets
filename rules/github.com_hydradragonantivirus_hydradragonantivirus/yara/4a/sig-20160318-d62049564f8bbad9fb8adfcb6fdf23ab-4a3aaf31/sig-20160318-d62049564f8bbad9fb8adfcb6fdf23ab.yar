rule sig_20160318_d62049564f8bbad9fb8adfcb6fdf23ab {
  meta:
    description = "datamaliciousorder - file 20160318_d62049564f8bbad9fb8adfcb6fdf23ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5954a60c2d569b47c59c6d7ea49351f918e2876c2aea2212f048caaef73cc6b6"

  strings:
    $s1  = "var mcyXs = \"ain!\";var e2 = \"y \\x61g\";var lMLzQ = \"e, \\x74r\";var HysV = \"s\";var EVf = \"Plea\";var pVn = \"68162\";var" ascii
    $s2  = "\";var z = function wfcjz() {return WScript[(function q(){return MhTw;}()) + (function pOnsE(){return io;}()) + (function ITTi()" ascii
    $s3  = "}()) + (function IVD(){return AKub;}()) + (function zAb(){return r;}()); Yj = AY(); sdrk = WScript[(function GXh(){return MhTw;}" ascii
    $s4  = "ction bhu(){return I;}()) + (function GL(){return TrVMd;}()) + (pVn);}else{WScript.Echo((function Btbs(){return EVf;}()) + (func" ascii
    $s5  = "on D0(){return bP;}()) + (Xt) + (function Y1(){return r1;}())] < 4 ) {WScript[(function eY(){return cY;}()) + (function m(){retu" ascii
    $s6  = "on WzvbN(){return RCPai;}()) + (function pm(){return dXdB;}()) + (OB)]();WScript[(function W(){return cY;}()) + (function Uj(){r" ascii
    $s7  = "W) + (function IZS(){return RCPai;}()) + (function S(){return dXdB;}()) + (function IeHo(){return OB;}())]();WScript[(function s" ascii
    $s8  = "rn KgWv;}()) + (pWleD)](zErd() * 10)};T = WScript[Y()]((function M(){return iJyOc;}()) + (function AvyD(){return RirEZ;}()) + (f" ascii
    $s9  = "nwKA){return cT - nwKA;};function Y(){return (MhTw) + (function BCL(){return io;}()) + (YOW);};function zErd(){return 22;};funct" ascii
    $s10 = "for (var c0 = 0; c0 < zErd() * 1; c0++){if (QKAz() != 0){R = true;c = true;break;}}function hoT() {return R && c;};if (hoT()){Vf" ascii
    $s11 = "return t;}()) + (Yn), false);sdrk[(function uWQgp(){return J;}())]();while (sdrk[(function ZS(){return flB;}()) + (cz) + (functi" ascii
    $s12 = "jxYcF(){return y;}())] = 1;T[(VQwj) + (function b1(){return KY;}())](sdrk[(function jl(){return dtBUk;}()) + (function z1(){retu" ascii
    $s13 = "n Ttpg(){return NMyb;}())]();var oQS = G[(function inQm(){return YFFLo;}()) + (jFFS) + (function Eu(){return IZuW;}()) + (functi" ascii
    $s14 = "+ (function F(){return fO;}()) + (klqI) + (function PNt(){return DOLh;}()) + (function hSlXi(){return j;}()) + (function Resd(){" ascii
    $s15 = "unction Nn(){return Xw;}()) + (function WX(){return Xuth;}()) + (eO));T[((m0))]();T[(function wS(){return BPUp;}()) + (function " ascii
    $s16 = "n FD(){return edTf;}()) + (function TE(){return n;}()));}();function u(JsMz){z[(D)](JsMz, 0, 0);};function AY(){return (function" ascii
    $s17 = " nyPQ(){return Dno;}()) + (KfF) + (function TeG(){return zPnhA;}()) + (function Ue(){return GDe;}()) + (ZW);};function Ywod(cT, " ascii
    $s18 = " Rwfo;}()) + (function afo(){return lser;}())) + (Wch) + (xMyHp) + (function TvH(){return vEqD;}()) + (function Iwi(){return n0;" ascii
    $s19 = "function nt(){return k;}()) + (function z0(){return b0;}()) + (function lLn(){return sF;}()) + (function r0(){return KVuBM;}()) " ascii
    $s20 = "tion tgx(){return HysV;}()) + (function Nh(){return lMLzQ;}()) + (function up(){return e2;}()) + (function slK(){return mcyXs;}(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}