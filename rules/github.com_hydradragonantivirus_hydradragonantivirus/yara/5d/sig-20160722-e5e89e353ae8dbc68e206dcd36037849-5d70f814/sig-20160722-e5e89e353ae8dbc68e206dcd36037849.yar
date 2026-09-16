rule sig_20160722_e5e89e353ae8dbc68e206dcd36037849 {
  meta:
    description = "datamaliciousorder - file 20160722_e5e89e353ae8dbc68e206dcd36037849.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e92b8e7fcddff5f98868fb48baef1b78e17071fcba891a538d20eeb035858b95"

  strings:
    $s1  = "    var Gx3 = WScript[DVu(DBo) + (function LPd6(){return Xp6;}()) + Ol7 + XCl](Vv9 + Qc + Ey + Oy);" fullword ascii
    $s2  = "    var We = WScript[DBo + Xp6 + (function Mv0(){return Ol7;}()) + XCl](Hy3 + QHu + NGu4 + Dk + CGr1 + MWz8);" fullword ascii
    $s3  = "Zb[Po](Lr8 + CHg2 + (function IZe(){return Dz5;}()));" fullword ascii
    $s4  = "function Qn7(By){return By;};function WBc(QHx4){return QHx4;};var XGx = \"am\" + \"\";" fullword ascii
    $s5  = "function Zo(Hg3){return Hg3;};var Nk = \"le\" + \"\";" fullword ascii
    $s6  = "function Wp(Lb){return Lb;};var HEr8 = \"oFile\" + \"\";" fullword ascii
    $s7  = "function NGs4(FNi7){return FNi7;};var WTg2 = \"ta\" + \"\";" fullword ascii
    $s8  = "function FFn6(TMy9){return TMy9;};var TAf = \"ll\" + \"\";" fullword ascii
    $s9  = "function BNx0(DXc){return DXc;};var VBo8 = \"nt\" + \"\";" fullword ascii
    $s10 = "function DVu(Le){return Le;};var XCl = \"ect\" + \"\";" fullword ascii
    $s11 = "function JHh(PXv2){return PXv2;};var XSp = \"aType\" + \"\";" fullword ascii
    $s12 = "function Qu0(Us2){return Us2;};var CCj1 = \"%/\" + \"\";" fullword ascii
    $s13 = "function UNi6(ERj9){return ERj9;};function QZk(Dt6){return Dt6;};function VKc(Ge7){return Ge7;};var BXr5 = \"ct\" + \"\";" fullword ascii
    $s14 = "var v_binpath=Lr8+Wj5+(function Lt0(){return QYp1;}());" fullword ascii
    $s15 = "function NRw(Et, Ma) {" fullword ascii
    $s16 = "function YUb(NUl, Ma)" fullword ascii
    $s17 = "   IDt9 = Bu[(function STy1(){return Sg8;}()) + SGp9 + Zo(Qu) + YYb + (function Qv(){return Nk;}())](Ma, QRq4, true)" fullword ascii
    $s18 = "   IDt9 = Bu[Sg8 + SGp9 + (function Wh0(){return Qu;}()) + YYb + (function Ni0(){return Nk;}())](Ma, Qn);" fullword ascii
    $s19 = "    var Cr = We[Mk1 + BNx0(Bo) + (function Ux9(){return Jq2;}()) + CYs0 + VBo8](LTb + ITo9 + GNr + NGs4(WTg2));" fullword ascii
    $s20 = "   PLr0 = IDt9[Sb + (function Qq9(){return JTc8;}())]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}