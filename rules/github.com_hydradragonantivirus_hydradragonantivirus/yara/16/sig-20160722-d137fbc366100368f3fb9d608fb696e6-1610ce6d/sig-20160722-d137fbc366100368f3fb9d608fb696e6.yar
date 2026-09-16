rule sig_20160722_d137fbc366100368f3fb9d608fb696e6 {
  meta:
    description = "datamaliciousorder - file 20160722_d137fbc366100368f3fb9d608fb696e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0104355fe6c75a2879c1e433a88433d11e8e8895c8b34b080b63454c65be9d19"

  strings:
    $s1  = "    var Rl9 = WScript[(function FFz8(){return Lp6;}()) + WYf2(CYx) + Bu9](BGl + QGc(Tn) + VRk + (function SKx(){return WGk;}()) " ascii
    $s2  = "    var Qo = WScript[Lp6 + CYx + (function Xh8(){return Bu9;}())](Kw4(VDk4) + Nf + AIt);" fullword ascii
    $s3  = "    var Rl9 = WScript[(function FFz8(){return Lp6;}()) + WYf2(CYx) + Bu9](BGl + QGc(Tn) + VRk + (function SKx(){return WGk;}()) " ascii
    $s4  = "function PPo8(Er){return Er;};var Bs = \".e\" + \"\";" fullword ascii
    $s5  = "function ZQw(Uw6){return Uw6;};var ZAd9 = \"te\" + \"\";" fullword ascii
    $s6  = "function Kw4(Fj4){return Fj4;};var AIt = \"eam\" + \"\";" fullword ascii
    $s7  = "function VSp2(Xe){return Xe;};var Jp = \"e\" + \"\";" fullword ascii
    $s8  = "function Qu7(Md2){return Md2;};var Rx = \"ta\" + \"\";" fullword ascii
    $s9  = "function GOo5(ECk){return ECk;};function Cq(BTv){return BTv;};var Vv = \"ine\" + \"\";" fullword ascii
    $s10 = "function JTd2(Ce2){return Ce2;};function MKh8(ZBz){return ZBz;};function WYf2(UIy){return UIy;};var Bu9 = \"bject\" + \"\";" fullword ascii
    $s11 = "function QGc(Ox){return Ox;};var Kr = \"nt\" + \"\";" fullword ascii
    $s12 = "function AUr90(Xd3){return Xd3;};var IAa5 = \"e\" + \"\";" fullword ascii
    $s13 = "function Dr(Za0){return Za0;};function ULg2(KYr2){return KYr2;};function Um(Jq0){return Jq0;};function RHi(MMz1){return MMz1;};v" ascii
    $s14 = "function NHt(CNf){return CNf;};var ZRc6 = \"ue\" + \"\";" fullword ascii
    $s15 = "function Wu5(Ls9){return Ls9;};var ZYr7 = \"in\" + \"\";" fullword ascii
    $s16 = "function ZBo(ZQo){return ZQo;};var Gm = \"P%/\" + \"\";" fullword ascii
    $s17 = "function Rw9(Ii){return Ii;};var Ve = \"S\" + \"\";" fullword ascii
    $s18 = "function LLb2(GAk2){return GAk2;};var LIs = \"ell\" + \"\";" fullword ascii
    $s19 = "function Zd6(JWi9){return JWi9;};var Af = \"ment\" + \"\";" fullword ascii
    $s20 = "function WOg(AUr9, Gg6)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}