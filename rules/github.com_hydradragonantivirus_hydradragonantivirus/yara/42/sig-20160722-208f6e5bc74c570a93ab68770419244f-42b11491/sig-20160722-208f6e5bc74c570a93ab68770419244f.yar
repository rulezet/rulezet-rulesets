rule sig_20160722_208f6e5bc74c570a93ab68770419244f {
  meta:
    description = "datamaliciousorder - file 20160722_208f6e5bc74c570a93ab68770419244f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64caa95d282d17a81c9ae85bb9783ef1ee762dc0f656af10b70d9cf19d792339"

  strings:
    $s1  = "    var Qb5 = WScript[NIh(XPe) + Ph + (function Ot4(){return Cq0;}())]((function FLc7(){return Ps6;}()) + KYx + Am8 + Yw9 + Qs(E" ascii
    $s2  = "    var Qb5 = WScript[NIh(XPe) + Ph + (function Ot4(){return Cq0;}())]((function FLc7(){return Ps6;}()) + KYx + Am8 + Yw9 + Qs(E" ascii
    $s3  = "function Po7(Nc){return Nc;};var Yd = \"%/\" + \"\";" fullword ascii
    $s4  = "function Hj1(NTo){return NTo;};var Am1 = \"e\" + \"\";" fullword ascii
    $s5  = "function DZc8(Nk){return Nk;};var Uq6 = \"ent\" + \"\";" fullword ascii
    $s6  = "function Gk(Se0){return Se0;};var Qx7 = \"oFile\" + \"\";" fullword ascii
    $s7  = "Rf) + (function Vq(){return Dg;}()) + (function Bl(){return QRn;}()));" fullword ascii
    $s8  = "}()) + (function Mb9(){return Db;}())]);" fullword ascii
    $s9  = "function Qs(Sa){return Sa;};var QRn = \"ject\" + \"\";" fullword ascii
    $s10 = "function NIh(Zb){return Zb;};function Qb7(KZb){return KZb;};function EVo(Mt8){return Mt8;};var Cq0 = \"ct\" + \"\";" fullword ascii
    $s11 = "var v_binpath=Se+(function Fx(){return Pa;}())+(function Zo(){return ASi;}());" fullword ascii
    $s12 = "    EQm0[Ry9 + (function Ut4(){return BYz;}()) + Fx2] = \"bin.base64\";" fullword ascii
    $s13 = "    var DDs = WScript[Qb7(XPe) + Ph + Cq0](DAc8 + ARu6 + (function GCo(){return Qs7;}()) + VRy + LEe4(CAa));" fullword ascii
    $s14 = "function LEe4(Ft){return Ft;};var CAa = \"ument\" + \"\";" fullword ascii
    $s15 = "function NMf9(QFp, Cj2)" fullword ascii
    $s16 = "function Wu6(KFd6, Cj2) {" fullword ascii
    $s17 = "    EQm0[Sd] = Pe2[Dc3 + (function UPw(){return BFm;}())]();" fullword ascii
    $s18 = "    var Yt = Qb5[Gb2 + (function Bd(){return Ap;}())](KFd6);" fullword ascii
    $s19 = "   TBr3 = new ActiveXObject(Ps6 + (function TIs(){return KYx;}()) + (function EVt(){return Am8;}()) + Yw9 + (function Eu7(){retu" ascii
    $s20 = "    var EQm0 = DDs[DZc8(Et0) + We + Av0 + (function BNu(){return Xy9;}()) + (function CMo(){return Uq6;}())](Ma7 + VIu);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}