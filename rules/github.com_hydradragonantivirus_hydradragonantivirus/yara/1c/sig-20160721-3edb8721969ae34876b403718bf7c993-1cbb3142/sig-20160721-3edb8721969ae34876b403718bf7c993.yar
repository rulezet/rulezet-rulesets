rule sig_20160721_3edb8721969ae34876b403718bf7c993 {
  meta:
    description = "datamaliciousorder - file 20160721_3edb8721969ae34876b403718bf7c993.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0280d6e40176296725ae23ef9c58b71daea781df900981b5f8ac9ac27072aa43"

  strings:
    $s1  = "var QTa5=WScript[CZn + JGw6 + YXz(Jx) + Ot](YDm + Xi + DFs1(KRc) + (function FZf(){return AUu0;}()));" fullword ascii
    $s2  = "    var IQe = WScript[Qr3(CZn) + ODe(JGw6) + Jx + (function KMv1(){return Ot;}())](Sg7(Ro5) + Ck + QTy4 + Py(KHv7) + Bu + LVx1(R" ascii
    $s3  = "    var PRl = WScript[CZn + JGw6 + WLb(Jx) + Ot]((function HCo(){return Jq1;}()) + Ox + DBx1 + Ed + (function NAf(){return Hb;}(" ascii
    $s4  = "    var IQe = WScript[Qr3(CZn) + ODe(JGw6) + Jx + (function KMv1(){return Ot;}())](Sg7(Ro5) + Ck + QTy4 + Py(KHv7) + Bu + LVx1(R" ascii
    $s5  = "    var PRl = WScript[CZn + JGw6 + WLb(Jx) + Ot]((function HCo(){return Jq1;}()) + Ox + DBx1 + Ed + (function NAf(){return Hb;}(" ascii
    $s6  = "    var Uu = WScript[CZn + Yc(JGw6) + Jx + QRy6(Ot)](DLs + (function YOw0(){return Kq1;}()) + Xs2);" fullword ascii
    $s7  = "function Is(Yg2){return Yg2;};var PLy = \"t\" + \"\";" fullword ascii
    $s8  = "function Qr3(Na0){return Na0;};function ODe(Vg9){return Vg9;};function WLb(Mw){return Mw;};function Yc(UQd9){return UQd9;};funct" ascii
    $s9  = "var NMi=LEo1 + AZz + Ka + RVu8 + (function Gv(){return GXc1;}());" fullword ascii
    $s10 = ")) + (function TJc(){return LJo0;}()) + Is(PLy));" fullword ascii
    $s11 = "function Wg(LOp){return LOp;};function Fk5(CXg){return CXg;};var BNu1 = \"am\" + \"\";" fullword ascii
    $s12 = "function Yb(Cl){return Cl;};var Le2 = \"e\" + \"\";" fullword ascii
    $s13 = "function DFs1(HNq2){return HNq2;};var AUu0 = \"ell\" + \"\";" fullword ascii
    $s14 = "function Eu3(Op){return Op;};var AQx = \"e\" + \"\";" fullword ascii
    $s15 = "function Sg7(Ql5){return Ql5;};function Py(Uw){return Uw;};function LVx1(Vc2){return Vc2;};function Pt(Cu3){return Cu3;};var Kh " ascii
    $s16 = "function Ex9(Nj0){return Nj0;};function Di1(Vs){return Vs;};var Fk2 = \"ll\" + \"\";" fullword ascii
    $s17 = "function Bp(Xp2){return Xp2;};var Fv = \"ose\" + \"\";" fullword ascii
    $s18 = "function KBm5(ZXf7){return ZXf7;};var AWv0 = \"text\" + \"\";" fullword ascii
    $s19 = "function Iz(ALd7){return ALd7;};var MRc6 = \"ue\" + \"\";" fullword ascii
    $s20 = "ion QRy6(Vt){return Vt;};function YXz(Ss0){return Ss0;};var Ot = \"ct\" + \"\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}