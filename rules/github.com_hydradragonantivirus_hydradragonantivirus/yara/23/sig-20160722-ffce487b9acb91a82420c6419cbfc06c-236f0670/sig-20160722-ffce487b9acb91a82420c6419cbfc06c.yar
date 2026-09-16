rule sig_20160722_ffce487b9acb91a82420c6419cbfc06c {
  meta:
    description = "datamaliciousorder - file 20160722_ffce487b9acb91a82420c6419cbfc06c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb8ceba1a2cb48f2d71f4a86f7117cd4d291ff45db6449156e1fe035fac35cbf"

  strings:
    $s1  = "function BKk(Gl2){return Gl2;};var Ku = \"Shell\" + \"\";" fullword ascii
    $s2  = "    var Jf = WScript[BOu + LHv + Vn + Gy7(Jc)](OCt + (function YNr(){return Yg2;}()) + Iz3 + Qj8 + NPa0 + YMx6 + Bt);" fullword ascii
    $s3  = "    var Vx = WScript[EHu(BOu) + LHv + Vn + Jc](NAp(AXm) + (function Ia6(){return Rt9;}()) + (function Np1(){return PZh0;}()) + V" ascii
    $s4  = "    var Vx = WScript[EHu(BOu) + LHv + Vn + Jc](NAp(AXm) + (function Ia6(){return Rt9;}()) + (function Np1(){return PZh0;}()) + V" ascii
    $s5  = "    var MDt = WScript[BOu + LHv + Vn + Jc](Jd3 + Xu + Cm + PWb0 + (function CPc9(){return Ga2;}()));" fullword ascii
    $s6  = "function CFh(AMh9){return AMh9;};var YIb0 = \"e\" + \"\";" fullword ascii
    $s7  = "function KFh5(Rh4){return Rh4;};var CEj4 = \"le\" + \"\";" fullword ascii
    $s8  = "var SIh=AAx1 + Gd + (function Ur(){return Ac10;}());" fullword ascii
    $s9  = "function Vy(HIb6){return HIb6;};var Cp0 = \"All\" + \"\";" fullword ascii
    $s10 = "function Gy7(RMr){return RMr;};function EHu(LFa){return LFa;};function BPz(Pv){return Pv;};function LHm9(Fn2){return Fn2;};var J" ascii
    $s11 = "var AAx1=Yd + Kw + (function FAf8(){return WBq6;}()) + OXb1;" fullword ascii
    $s12 = "function Ry5(Ah5){return Ah5;};function HRw(QEc){return QEc;};var NMr = \"nt\" + \"\";" fullword ascii
    $s13 = "h(REx) + (function ZCp(){return FHl5;}()) + JRy3(Xh));" fullword ascii
    $s14 = "function TGm(WMq3){return WMq3;};var Ay4 = \"MP%/\" + \"\";" fullword ascii
    $s15 = "function NAp(Gx){return Gx;};function Vh(Mx5){return Mx5;};function JRy3(DQd){return DQd;};var Xh = \"t\" + \"\";" fullword ascii
    $s16 = "function VUh(JYy){return JYy;};var Ju = \"File\" + \"\";" fullword ascii
    $s17 = "    var TNu7 = Co[Hr + ZCq6 + (function NMb(){return YVv;}()) + (function GBk7(){return YJp6;}())](Zy7, URf);" fullword ascii
    $s18 = "function Gy7(RMr){return RMr;};function EHu(LFa){return LFa;};function BPz(Pv){return Pv;};function LHm9(Fn2){return Fn2;};var J" ascii
    $s19 = "function Sx(Zk1, KWs) {" fullword ascii
    $s20 = "function Lo2(Su8, KWs)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}