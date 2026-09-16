rule sig_20160721_9bff741eb7c76982227c10b4f20ea35c {
  meta:
    description = "datamaliciousorder - file 20160721_9bff741eb7c76982227c10b4f20ea35c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab136815a0ded38080b379d6732c8f990306a8325d3b70ae9b03ecba84d96f78"

  strings:
    $s1  = "    var Nn = WScript[Dg3(Dm) + ZPx + Mq + FFq1](TEj1 + (function Hd3(){return DFu;}()) + (function Bd7(){return Tn5;}()));" fullword ascii
    $s2  = "    var Et = WScript[Dm + ZPx + (function Zl(){return Mq;}()) + (function Wb3(){return FFq1;}())](TDb(Nl) + GId + (function Hd()" ascii
    $s3  = "    var Et = WScript[Dm + ZPx + (function Zl(){return Mq;}()) + (function Wb3(){return FFq1;}())](TDb(Nl) + GId + (function Hd()" ascii
    $s4  = "function MBn3(Lg){return Lg;};function LJu(In){return In;};function WQy(UMz){return UMz;};var Sw9 = \"le\" + \"\";" fullword ascii
    $s5  = "function VRo5(DGp4){return DGp4;};function Dg3(GDg){return GDg;};var FFq1 = \"ct\" + \"\";" fullword ascii
    $s6  = "function Xx8(MIz){return MIz;};var Kd = \"ine\" + \"\";" fullword ascii
    $s7  = "function HZl(DVm6){return DVm6;};function SMj(Hl6){return Hl6;};var WUt1 = \"ent\" + \"\";" fullword ascii
    $s8  = "{return Fy2;}()) + Fs + Vr + NCl + KFz3);" fullword ascii
    $s9  = "function JCl(Ak){return Ak;};function Wu0(Uu1){return Uu1;};var AEh = \"f\" + \"\";" fullword ascii
    $s10 = "function VPj3(LPc0){return LPc0;};var Rz7 = \"e\" + \"\";" fullword ascii
    $s11 = "var LDf=WLg.ExpandEnvironmentStrings(Hf0 + (function Tv6(){return MUd4;}()));" fullword ascii
    $s12 = "var DLy6=Lq + Se + (function Fl(){return Ki;}());" fullword ascii
    $s13 = "function AQx(Ci){return Ci;};var La = \"m\" + \"\";" fullword ascii
    $s14 = "WLg[Bv](DLy6 + (function XLv2(){return LNd1;}()) + Cj5);" fullword ascii
    $s15 = "function Cc4(FVm){return FVm;};var TRz2 = \"le\" + \"\";" fullword ascii
    $s16 = "turn NCl;}()) + (function TVa3(){return KFz3;}()))" fullword ascii
    $s17 = "var v_binpath=DLy6+IVb4+(function Eg(){return AIp;}());" fullword ascii
    $s18 = "function Ft4(DPk9, WZn6) {" fullword ascii
    $s19 = "function Om(DDi6, WZn6)" fullword ascii
    $s20 = "function TDb(ICa9){return ICa9;};var KFz3 = \"ect\" + \"\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}