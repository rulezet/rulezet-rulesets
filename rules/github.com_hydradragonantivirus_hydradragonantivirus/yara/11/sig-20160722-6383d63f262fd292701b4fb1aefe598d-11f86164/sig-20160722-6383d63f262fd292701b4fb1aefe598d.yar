rule sig_20160722_6383d63f262fd292701b4fb1aefe598d {
  meta:
    description = "datamaliciousorder - file 20160722_6383d63f262fd292701b4fb1aefe598d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481d4cb31b1a250c5039fd220b81173d24b0b0178514db314855a0f199a4294c"

  strings:
    $s1  = "var GVr9=WScript[TCx3 + RGk + KFd + Zt](Sd0 + Gx0 + (function Tl(){return Wr;}()) + (function Zz(){return Cv;}()) + AGc);" fullword ascii
    $s2  = "    var Gq = WScript[TCx3 + (function Km(){return RGk;}()) + CNy2(KFd) + Cn2(Zt)](GJv + Bv + Ld2(HMk7) + FIf);" fullword ascii
    $s3  = "    var UWa8 = WScript[TCx3 + RGk + KFd + (function Zj(){return Zt;}())](Hr1(ONt2) + CQd + (function Pf4(){return Ri0;}()));" fullword ascii
    $s4  = "function Hr1(Qw9){return Qw9;};var Ri0 = \"ream\" + \"\";" fullword ascii
    $s5  = "function Ld2(Dw){return Dw;};var FIf = \"ument\" + \"\";" fullword ascii
    $s6  = "function Yd(CQb){return CQb;};function YTc(Aj){return Aj;};var Bk3 = \"ZKDP\" + \"\";" fullword ascii
    $s7  = "function Ul9(WBm){return WBm;};var DEa8 = \"Open\" + \"\";" fullword ascii
    $s8  = "function CNy2(Pe){return Pe;};function Cn2(XVb){return XVb;};var Zt = \"t\" + \"\";" fullword ascii
    $s9  = "GVr9[(function RLy5(){return Jk8;}())](Gu + Gw3 + XJp);" fullword ascii
    $s10 = "function Zg5(Ev8){return Ev8;};function RGc(Xm1){return Xm1;};function SSe9(Wy9){return Wy9;};var Gg = \"bject\" + \"\";" fullword ascii
    $s11 = "function TJo(Tj){return Tj;};var Wd7 = \"ata\" + \"\";" fullword ascii
    $s12 = "var WBn=OWw8 + Yd(Pq) + (function UMs3(){return Ug;}()) + (function Af6(){return Lm2;}()) + YTc(Bh) + NBl9 + Bk3;" fullword ascii
    $s13 = "function By9(JAw){return JAw;};var Bi = \"m\" + \"\";" fullword ascii
    $s14 = "function Df1(VEc9){return VEc9;};var AFv5 = \".b\" + \"\";" fullword ascii
    $s15 = "function AHa(Oj){return Oj;};var Xz3 = \"alue\" + \"\";" fullword ascii
    $s16 = "function PCh(Rv, SWq0)" fullword ascii
    $s17 = "function EWl(ZOg, SWq0) {" fullword ascii
    $s18 = "   RGd7[(function Sd(){return NZt;}()) + Jz](Rv);" fullword ascii
    $s19 = "    Tg3[XRk + (function JDt6(){return Ik1;}())]();" fullword ascii
    $s20 = "   STd9 = RGd7[SJj + (function Ld5(){return Oe9;}())]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}