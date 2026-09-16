rule sig_20160721_e95513a3401e8f0f4746fbf49c819b7e {
  meta:
    description = "datamaliciousorder - file 20160721_e95513a3401e8f0f4746fbf49c819b7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5d19e0429d10a41a7541c67d3f21d01d809700ef78f98c9bc8f27d8b08bb2af"

  strings:
    $s1  = "var Zs=WScript[Ig + Dr + CHj + (function DWt1(){return En;}()) + Pm3](Mv0 + WDy + Ou(MGn));" fullword ascii
    $s2  = "    var XAh = WScript[Ig + Dr + CHj + En + WVr(Pm3)](Xp + RVl + Wq2 + (function PZt(){return GDl;}()) + ODq6 + Sp + Fa7 + (funct" ascii
    $s3  = "    var Vs = WScript[Ig + Dr + CHj + En + Pm3](BRj + Ha6 + VPv9 + (function Rx2(){return Bc6;}()) + OQw5);" fullword ascii
    $s4  = "    var XAh = WScript[Ig + Dr + CHj + En + WVr(Pm3)](Xp + RVl + Wq2 + (function PZt(){return GDl;}()) + ODq6 + Sp + Fa7 + (funct" ascii
    $s5  = "function UDt(Xv){return Xv;};var Pg = \"pe\" + \"\";" fullword ascii
    $s6  = "function Xi(Fi8){return Fi8;};var SGl8 = \"oFile\" + \"\";" fullword ascii
    $s7  = "function ZNq4(RZz){return RZz;};var Ne = \"nt\" + \"\";" fullword ascii
    $s8  = "function CSi(KQa7){return KQa7;};var DKl4 = \"ne\" + \"\";" fullword ascii
    $s9  = "function RTl2(ZJr){return ZJr;};var Qp = \"Value\" + \"\";" fullword ascii
    $s10 = "function Kj0(Hn){return Hn;};var NPz2 = \"P%/\" + \"\";" fullword ascii
    $s11 = "function CHk9(Ak1){return Ak1;};var EGp1 = \"e\" + \"\";" fullword ascii
    $s12 = "ion KYh2(){return AJm;}()) + HYq);" fullword ascii
    $s13 = "function LUx3(KOu9){return KOu9;};function Hc(FVn){return FVn;};var HYq = \"ct\" + \"\";" fullword ascii
    $s14 = "function WVr(Ky){return Ky;};var Pm3 = \"t\" + \"\";" fullword ascii
    $s15 = "function Gl3(Jw8){return Jw8;};var LKs = \"File\" + \"\";" fullword ascii
    $s16 = "function ZTs(Jv){return Jv;};var RQj8 = \"ll\" + \"\";" fullword ascii
    $s17 = "function Ou(Bv){return Bv;};var MGn = \"ell\" + \"\";" fullword ascii
    $s18 = "function UBb(CJo9){return CJo9;};var TAo = \"te\" + \"\";" fullword ascii
    $s19 = "function IJb1(PGz6){return PGz6;};var Pp0 = \".b\" + \"\";" fullword ascii
    $s20 = "on XBd7(){return Cb8;}()));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}