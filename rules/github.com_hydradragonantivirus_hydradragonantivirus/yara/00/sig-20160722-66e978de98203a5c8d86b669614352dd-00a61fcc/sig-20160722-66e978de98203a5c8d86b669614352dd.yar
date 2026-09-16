rule sig_20160722_66e978de98203a5c8d86b669614352dd {
  meta:
    description = "datamaliciousorder - file 20160722_66e978de98203a5c8d86b669614352dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad65b0f50de67fbb690d3b57695f6ea0955e764d9ef8535c8e0abc030c97dedc"

  strings:
    $s1  = "var KQa=WScript[(function JSp4(){return Mv9;}()) + (function Bh(){return NKl3;}()) + LPp(Of3) + Pm8(Pg3) + (function Aq8(){retur" ascii
    $s2  = "var KQa=WScript[(function JSp4(){return Mv9;}()) + (function Bh(){return NKl3;}()) + LPp(Of3) + Pm8(Pg3) + (function Aq8(){retur" ascii
    $s3  = "    var QAx = WScript[Mv9 + NKl3 + Of3 + (function EJw(){return Pg3;}()) + Bo(Kz3)](Hm8 + Uo + HKx + Yd);" fullword ascii
    $s4  = "function Ty(Ob1){return Ob1;};var VOa6 = \".b\" + \"\";" fullword ascii
    $s5  = "function Cu5(WOy){return WOy;};function Qr9(Dv1){return Dv1;};var ABf0 = \"t\" + \"\";" fullword ascii
    $s6  = "function DQq6(IIk5){return IIk5;};var Ml = \"ll\" + \"\";" fullword ascii
    $s7  = "n Kz3;}())](DQq6(El5) + URc1 + XZt2 + (function He(){return Ml;}()));" fullword ascii
    $s8  = "function Gz6(Ej9){return Ej9;};var Kr7 = \"aType\" + \"\";" fullword ascii
    $s9  = "Pp(Aj){return Aj;};function Pm8(ANo){return ANo;};var Kz3 = \"t\" + \"\";" fullword ascii
    $s10 = "function HWs(Og){return Og;};var TOe = \"en\" + \"\";" fullword ascii
    $s11 = "function LMd(XXp){return XXp;};function Gz3(Oa){return Oa;};function Bb(Po4){return Po4;};function Bo(Tk){return Tk;};function L" ascii
    $s12 = "function Iv0(QUn){return QUn;};function Fr1(Dn0){return Dn0;};function QRn(Zy){return Zy;};var Cj5 = \"se\" + \"\";" fullword ascii
    $s13 = "    Ac[Gz6(Ps8) + (function WGz(){return Kr7;}())] = \"bin.base64\";" fullword ascii
    $s14 = "    var NSd = WScript[Gz3(Mv9) + NKl3 + Of3 + Bb(Pg3) + Kz3](Cu5(ECa) + Id9 + (function Rr(){return Oo;}()) + Qr9(Rp3) + ABf0);" fullword ascii
    $s15 = "function LMd(XXp){return XXp;};function Gz3(Oa){return Oa;};function Bb(Po4){return Po4;};function Bo(Tk){return Tk;};function L" ascii
    $s16 = "function Dd(Ul, Ds) {" fullword ascii
    $s17 = "function Bc(KVs, Ds)" fullword ascii
    $s18 = "    var Ja3 = Fo[JKo + Vu + Pi1 + (function Wu2(){return Zv8;}()) + BWr](TAo6, Lu);" fullword ascii
    $s19 = "    var Ac = NSd[DXq + PSs5 + POe0 + Rd](Te + (function Fn(){return Hd;}()) + Ja1);" fullword ascii
    $s20 = "   Lm1[(function YXo6(){return Bj;}()) + TNr0](KVs);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}