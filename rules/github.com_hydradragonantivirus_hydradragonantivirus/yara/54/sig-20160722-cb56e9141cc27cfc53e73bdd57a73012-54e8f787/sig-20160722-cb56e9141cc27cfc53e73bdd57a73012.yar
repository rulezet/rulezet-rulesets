rule sig_20160722_cb56e9141cc27cfc53e73bdd57a73012 {
  meta:
    description = "datamaliciousorder - file 20160722_cb56e9141cc27cfc53e73bdd57a73012.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adc47004b4da234de9af44ca1bd87c8cb48c2915fa2b16b2a7832674d2f676cb"

  strings:
    $s1  = "    var BNl9 = WScript[HEk + CJl + TYi8(IQd1) + IGh](CXt1 + XVo + REx + FBk3 + IPm + (function OSg(){return DUw9;}()) + (functio" ascii
    $s2  = "    var BNl9 = WScript[HEk + CJl + TYi8(IQd1) + IGh](CXt1 + XVo + REx + FBk3 + IPm + (function OSg(){return DUw9;}()) + (functio" ascii
    $s3  = "    var EAf = WScript[HEk + CJl + IQd1 + IGh]((function SXt(){return Lt8;}()) + BGa(Yr) + Us8 + YCf(Wt0));" fullword ascii
    $s4  = "    var SYa8 = WScript[HEk + CJl + IQd1 + (function FMo(){return IGh;}())](GAv + Kr(Qf) + Rc3 + SXu2 + Cn1);" fullword ascii
    $s5  = "function BDq(Gm){return Gm;};var Ew7 = \"ype\" + \"\";" fullword ascii
    $s6  = "function VSm4(SNu1){return SNu1;};var UGo = \"ent\" + \"\";" fullword ascii
    $s7  = "n XDx0(){return Rf;}()) + EGp + Np(Dm));" fullword ascii
    $s8  = "function Bz3(HCs){return HCs;};var Ja4 = \"x\" + \"\";" fullword ascii
    $s9  = "function BGa(Ic2){return Ic2;};function YCf(YNx){return YNx;};var Wt0 = \"eam\" + \"\";" fullword ascii
    $s10 = "function Gw4(YXe){return YXe;};var Io = \"e\" + \"\";" fullword ascii
    $s11 = "function Kr(VVj4){return VVj4;};var Cn1 = \"nt\" + \"\";" fullword ascii
    $s12 = "function Np(KUq){return KUq;};function MGj2(Et){return Et;};function DNv5(Pc){return Pc;};var Dm = \"ject\" + \"\";" fullword ascii
    $s13 = "function TYi8(Ue){return Ue;};var IGh = \"ject\" + \"\";" fullword ascii
    $s14 = "function CXn(Xn0, MPl) {" fullword ascii
    $s15 = "function Pv(GOx, MPl)" fullword ascii
    $s16 = "   IUm = JXz4[(function BQq(){return OOx7;}()) + YBe + Ta](MPl, FRl7, true)" fullword ascii
    $s17 = "    var De7 = VWs6[OCx0 + Kr9 + Il8 + FXp5 + Ku + (function JWl2(){return BMc;}())](Ix7, VFo);" fullword ascii
    $s18 = "    EAf[CYe7 + Ai1](EIe4[Ac4 + (function Sk9(){return OBy;}()) + Tp]);" fullword ascii
    $s19 = "    var VWs6 = BNl9[(function Hp(){return Ld1;}()) + KYz0](Xn0);" fullword ascii
    $s20 = "    EAf[(function RBq(){return To1;}()) + YDe0 + Xq](MPl, ECd4);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}