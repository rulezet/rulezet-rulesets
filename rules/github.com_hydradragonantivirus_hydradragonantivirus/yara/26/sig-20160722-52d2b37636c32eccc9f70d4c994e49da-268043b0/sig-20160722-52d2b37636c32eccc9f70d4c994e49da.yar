rule sig_20160722_52d2b37636c32eccc9f70d4c994e49da {
  meta:
    description = "datamaliciousorder - file 20160722_52d2b37636c32eccc9f70d4c994e49da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a1c24662e61c7bbfc6d74a33adee2a07627f8c47676873d131bcaf4d7329866"

  strings:
    $s1  = "    var Bi8 = WScript[XAn7 + (function Ba5(){return JKb7;}()) + EFs5 + Do3](Qn0 + HGu(ZWc9) + (function Zq2(){return MLg;}()) + " ascii
    $s2  = "    var Bi8 = WScript[XAn7 + (function Ba5(){return JKb7;}()) + EFs5 + Do3](Qn0 + HGu(ZWc9) + (function Zq2(){return MLg;}()) + " ascii
    $s3  = "    var GVx3 = WScript[ZZk0(XAn7) + (function Qk(){return JKb7;}()) + EFs5 + Do3](Ig6 + Ks + SQz + Ln4(Ye) + Fx(FOy) + UKd + ACm" ascii
    $s4  = "    var GVx3 = WScript[ZZk0(XAn7) + (function Qk(){return JKb7;}()) + EFs5 + Do3](Ig6 + Ks + SQz + Ln4(Ye) + Fx(FOy) + UKd + ACm" ascii
    $s5  = "function PLg0(Jg1){return Jg1;};var Gm1 = \"File\" + \"\";" fullword ascii
    $s6  = "var Np=JGt1.ExpandEnvironmentStrings(Lh + (function SAi1(){return Tg6;}()));" fullword ascii
    $s7  = "function Hh(OVe2){return OVe2;};var SLc = \"Value\" + \"\";" fullword ascii
    $s8  = "function PTo5(Iy5){return Iy5;};var Vp1 = \"xt\" + \"\";" fullword ascii
    $s9  = "function QDg1(Zo3){return Zo3;};var VLm5 = \"ype\" + \"\";" fullword ascii
    $s10 = "function TFf(ITs3){return ITs3;};var DZk2 = \"ream\" + \"\";" fullword ascii
    $s11 = "function HGu(Wj){return Wj;};var Ty = \"ent\" + \"\";" fullword ascii
    $s12 = "function HNl(QKs8){return QKs8;};var Dc = \"Line\" + \"\";" fullword ascii
    $s13 = "var RMd=Om7 + Hb6 + (function Vo6(){return VYp;}());" fullword ascii
    $s14 = "function Pb(Qf){return Qf;};var ZHb9 = \"a\" + \"\";" fullword ascii
    $s15 = "function Ln4(Sn){return Sn;};function Fx(Te9){return Te9;};function OCo7(LOy){return LOy;};function Rz7(ZRt1){return ZRt1;};var " ascii
    $s16 = "function Qn4(Cm5){return Cm5;};var UNp = \"e\" + \"\";" fullword ascii
    $s17 = "function ZZk0(Zv3){return Zv3;};function Vq7(Sn0){return Sn0;};function Ld(Ld0){return Ld0;};var Do3 = \"t\" + \"\";" fullword ascii
    $s18 = "function Eu0(Qz5, Jr1)" fullword ascii
    $s19 = "function Ln4(Sn){return Sn;};function Fx(Te9){return Te9;};function OCo7(LOy){return LOy;};function Rz7(ZRt1){return ZRt1;};var " ascii
    $s20 = "function St5(PSi2, Jr1) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}