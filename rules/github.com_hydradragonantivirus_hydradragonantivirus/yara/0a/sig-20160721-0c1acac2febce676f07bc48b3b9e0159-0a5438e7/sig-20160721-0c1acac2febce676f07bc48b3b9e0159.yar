rule sig_20160721_0c1acac2febce676f07bc48b3b9e0159 {
  meta:
    description = "datamaliciousorder - file 20160721_0c1acac2febce676f07bc48b3b9e0159.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97117fbfa8c18739971f636952aa2a2e814dfd87231cdd7b78f5fad17a39d08b"

  strings:
    $s1  = "var QJt=WScript[Pl7 + Dr(Et) + Ae8](BMc + Dw0 + ZMf9 + (function LFu(){return Nf;}()));" fullword ascii
    $s2  = "    var LKl1 = WScript[(function Wk(){return Pl7;}()) + Et + Ae8](QYl + Et6 + Ry1 + He6);" fullword ascii
    $s3  = "QJt[ZEa](HEy + Qz5 + (function Sw1(){return Hw3;}()));" fullword ascii
    $s4  = "function FFp4(PWh3){return PWh3;};var Ly = \"Write\" + \"\";" fullword ascii
    $s5  = "function BZh5(KHt){return KHt;};function EVp5(Jl){return Jl;};var Ri = \"ct\" + \"\";" fullword ascii
    $s6  = "function UBn(ZAw){return ZAw;};var RUu5 = \"e\" + \"\";" fullword ascii
    $s7  = "function Fc(Lu0){return Lu0;};var HVe6 = \"Type\" + \"\";" fullword ascii
    $s8  = "var Xz7=QJt.ExpandEnvironmentStrings((function ASz(){return CZn8;}()) + Cu);" fullword ascii
    $s9  = "function Xa(XKx8){return XKx8;};var Bi6 = \"lue\" + \"\";" fullword ascii
    $s10 = "function KLn1(Xm7){return Xm7;};var Uz1 = \"e\" + \"\";" fullword ascii
    $s11 = "function Dr(Ey8){return Ey8;};var Ae8 = \"ect\" + \"\";" fullword ascii
    $s12 = "function Gq(Nb){return Nb;};function GDe6(Io){return Io;};var DQr7 = \"ment\" + \"\";" fullword ascii
    $s13 = "function Gi4(OCr3){return OCr3;};function Ng7(BTn9){return BTn9;};var WFn1 = \"Line\" + \"\";" fullword ascii
    $s14 = "function WSy(NMq9){return NMq9;};var ZDk5 = \".b\" + \"\";" fullword ascii
    $s15 = "function IYq(Rd, CSl) {" fullword ascii
    $s16 = "function YHc6(Ox, CSl)" fullword ascii
    $s17 = "   Ox5 = DOf4[UBn(Yp4) + Gf + (function DBd3(){return Vm;}()) + RUu5](CSl, Yk1, true)" fullword ascii
    $s18 = "    LFw[Td] = Vz0[BJb7 + (function XFl(){return TZj;}())]();" fullword ascii
    $s19 = "    var Vz0 = JBn7[Nv6 + Fe4 + IDe6 + QNc + (function Uy(){return Pe6;}())](Kl0, KEs9);" fullword ascii
    $s20 = "   DOf4 = new ActiveXObject((function Ex8(){return XFt;}()) + EVp5(YDe) + HWf + ATt1 + OEu + GYx6 + As5 + (function SBg(){return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}