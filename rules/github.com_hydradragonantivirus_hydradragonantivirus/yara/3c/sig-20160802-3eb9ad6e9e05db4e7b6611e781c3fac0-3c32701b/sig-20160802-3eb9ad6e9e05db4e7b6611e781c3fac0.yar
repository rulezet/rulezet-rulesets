rule sig_20160802_3eb9ad6e9e05db4e7b6611e781c3fac0 {
  meta:
    description = "datamaliciousorder - file 20160802_3eb9ad6e9e05db4e7b6611e781c3fac0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "582bd4db0c6658197f40375948d0640edd94bda8d64e22108f4fa5d8e0ba14c1"

  strings:
    $x1  = "    var aTSh = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "\\n\\x09\\t}\\r\\n\\t\\t\\r\\n\\t\\tva\\x72 ARt=WScript[Jm + Fe + JHu8 + Ot8](Oa4(Ea)+JWz3+Tv6+Ep \\x2b Li4 + (function\\x20TBc(" ascii
    $s3  = "''+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nvar E" ascii
    $s4  = "\\nvar Ya=360\\x37 - 3\\x3605;\\r\\n\\x76ar UMc\\x3d\"437\";\\r\\n\\r\\nvar ERb=[S'+''+'\\x55f2+Kx2 + (function Fb(){retur\\x6e " ascii
    $s5  = "x0d\\nPa7[252]=8319;\\r\\nPa7[253\\x5d=17\\x38;\\r\\nPa7[2\\x354]=19363 - 9\\x3731;\\r\\nPa7[25\\x35]=160;\\x0d\\n\\t\\r\\n\\tva" ascii
    $s6  = " OXv9]], false);\\r\\n\\t\\t\\tSy\\x5b(f\\x75\\x6ection \\x47i2\\x28){r\\x65turn Mf;}()) + MVd1]();\\r\\n\\t\\t}\\r\\n\\x09\\t" ascii
    $s7  = "\\x2b(functi\\x6fn Ry0(){return Qq;}())+N\\x41m9, MSc5 + QRy5+RTo2(Lr8)\\x2bUn+Cl8\\x2bAe+Yy1 + \\x52i5+(function Xl2(\\x29{retu" ascii
    $s8  = "BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52Vy(M" ascii
    $s9  = "5\" + \"\";\\r\\nfunction KEx3(TEw){retur\\x6e TEw\\x3b};function OHs\\x30\\x28Lo){r\\x65t\\x75rn Lo\\x3b};var Ly0 = \"p\" + \"" ascii
    $s10 = "Wi2 + (function Ua(\\x29{return INw6;}()) + Wk9 + Es1 + VOw, \\x46t + D\\x51b + XEh\\x5d;\\r\\n\\r\\x0af\\x6fr (var OPj=0; OP\\x" ascii
    $s11 = "}())+\\x4f\\x6a2+Xs5 + Lq3, W\\x63+(function Ii(){return \\x4eLs;}\\x28)) + RGl2\\x2bHh+UIk+(function VEd(){return Uf;}()) + (fu" ascii
    $s12 = " (function EPo()\\x7breturn \\x57p\\x3b}()) + Xc\\x36 + Zb1(YUc) + Z\\x44o7 + Ol\\x20+ HMr4 + TX\\x658 + G\\x73\\x34 + Pa1);\\r" ascii
    $s13 = "c4\\x2b(fun\\x63tion Z\\x719(){re\\x74urn Nl;}\\x28))+Wn1+RWi+Po+Cy5\\x20+ Nn5+(function GNn(){return FYs1;}())+Rj\\x33(S\\x6a5)" ascii
    $s14 = "return EYf;\\x7d()));\\r\\nvar Te=Mz9[QSc + OXv\\x39];\\r\\nvar NVd=(M\\x6a + \\x28function Oi5(){return EGw;\\x7d()) \\x2b Dh5 " ascii
    $s15 = "nreturn Mat\\x68.floor(range * \\x28rawprng()\\x20+ (rawprng() * 0x200000 |\\x200\\x29 * 1.1102230\\x3246251565e-'+''+'16\\x29);" ascii
    $s16 = "\" + \"\\x22;\\r\\nvar BS\\x734\\x20= \"11\\x323\" + \"\";\\r\\nvar Mz\\x39=(BSs\\x34 + If(Kg),\\x20J\\x6c9 \\x2b CZy + IIk2 + (" ascii
    $s17 = "Su(\\x4dS\\x6c) + \\x58t6);\\r\\nvar UWy4=Pe0[QSc + (fu\\x6ection LBy(){return OX\\x76\\x39\\x3b}())];\\r\\n\\r\\nvar GRx5=1;\\r" ascii
    $s18 = "N\\x41e\\x30) + PJh]();\\r\\n \\x20  return NFc(\\x42w);\\r\\n};\\x0d\\n\\r\\n\\r\\nfunction NFc(\\x54\\x660)\\r\\n{ \\x20 \\r" ascii
    $s19 = "ENo];}\\r\\n\\t\\t\\x44q.p\\x75s\\x68(String[K\\x74 + Fd + XUw\\x20+ Eo\\x36](EFq\\x37));\\x0d\\n\\t}\\r\\n\\t\\r\\n\\tOg=\\x44q" ascii
    $s20 = "32830643653\\x386963e-\\x310\\x3b\\r\\x0a} e\\x6cse n = 0xefc8249\\x64;\\x0d\\n\\x7d;\\r\\nreturn mash;\\r\\n}\\r\\x0a\\r\\nvar " ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}