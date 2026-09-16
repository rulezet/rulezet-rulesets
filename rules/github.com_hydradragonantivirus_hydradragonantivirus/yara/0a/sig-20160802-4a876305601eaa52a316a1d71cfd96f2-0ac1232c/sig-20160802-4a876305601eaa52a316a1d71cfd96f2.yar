rule sig_20160802_4a876305601eaa52a316a1d71cfd96f2 {
  meta:
    description = "datamaliciousorder - file 20160802_4a876305601eaa52a316a1d71cfd96f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ad5f2026b1373ec7f5e3f7d65fc91ade2f93945b271e38eb53953e8448f05ab"

  strings:
    $s1  = "    var aRd9 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "[p] = t - (c\\x20= t\\x20| 0);\\r\\n}return random;}\\x28))\\x3b};\\r\\n\\r\\nfunction Mash() {\\r\\n\\x76a\\x72 n = 0xefc8\\x32" ascii
    $s3  = "tvar Sy\\x3dWScript[Vo + (function CYi(\\x29{return V\\x45d;}()\\x29\\x20\\x2b \\x28function ELr4(){return KQd9;}(\\x29) \\x2b" ascii
    $s4  = "gt\" + \"\";\\r\\nfunction Qg(Bt4){re\\x74urn \\x42t4;};var Oi0 =\\x20\\x22GET\" \\x2b \\x22\";\\r\\nf\\x75nction Hg0(Ww){return" ascii
    $s5  = "r \\x48Fz\\x3dnew Array(\\x29;\\r\\n\\tfor (var OPj\\x3d693\\x38 - 693\\x38; OPj < Tf0[JQu(QSc) + (\\x66unction Cn2(){return\\x2" ascii
    $s6  = "    var\\x20WHy0\\x3dWScript[(function PXo9()\\x7breturn Vo;}())\\x20+ V\\x45d + (function \\x53\\x53q(){return KQd9;}()\\x29 + " ascii
    $s7  = "return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x0" ascii
    $s8  = " \"q\" + \"\";\\r\\nva\\x72 AXa = \"/m\" + \"\"\\x3b\\r\\nvar La6\\x20= \"\\x6fm\" + \"\";\\r\\nfunction GTn6\\x28\\x57c){return" ascii
    $s9  = "t\\tSy[RFc4 \\x2b \\x48g\\x30(Yj0)](Qg(O\\x690), ERb[OE\\x716++ % ERb[QS\\x63 \\x2b OXv9]], false);\\r\\n\\t\\t\\t\\x53y[T\\x54v" ascii
    $s10 = "nction Zb1(\\x43'+''+'Zq){return \\x43\\x5aq;};var Pa1\\x20= \"l\" + \"\";\\r\\nvar Gs4 = \"lllll\" + \"\";\\r\\nvar TXe8 = \"ll" ascii
    $s11 = "724 + \\x54Xe8 + Gs4 + Pa1);\\r\\nvar Gz = \\x3672168;\\r\\nvar Id=NVd[QS\\x63\\x20\\x2b OXv9];\\r\\nvar Pe0=(Dv3 + KJd + (funct" ascii
    $s12 = " \"\";\\x0d\\nfunct\\x69on \\x55p(Wr6){return Wr6;\\x7d;va\\x72\\x20Wc6 = \"t\" + \"\";\\r\\x0avar ZOc9 = \"bjec\" \\x2b \"\";" ascii
    $s13 = "Fm0+V\\x6d+(function Zq9(){return \\x4el;}())+Wn1+RWi+Po, Cy5 + \\x4en5+(fu\\x6ection GNn\\x28){return FYs1;}()\\x29+Rj3(Sj5)+WS" ascii
    $s14 = "10;\\r\\n} \\x65lse n = 0xefc8249d;\\r\\n};\\r\\nreturn mash;\\x0d\\n}\\r\\n\\r\\x0avar Pe=\\x5bQAy4\\x20+\\x20WNj7 + COz + Ra " ascii
    $s15 = "9)]; O\\x50j++)\\r\\x0a\\t{\\x0d\\x0a\\t\\tvar \\x45Fq7=Tf0[\\x4d\\x4fs3 + (function Oy(){return AXy6;}()) + Rt](OP\\x6a);\\r\\n" ascii
    $s16 = "nfunction TTv(Yk){return Yk;}\\x3bvar\\x20HXb = \"sen\\x64\"\\x20+ \\x22\";\\r\\nva\\x72 EQk9 \\x3d \"\\x68\" + \"\";\\r\\nvar " ascii
    $s17 = " SGv(KLy5){re\\x74urn KLy5;};function JQu(KKh4){return KKh\\x34;};var OXv9 = \\x22gth\" + \"\";\\r\\nvar QSc = \"len\" + \\x22\"" ascii
    $s18 = ";v\\x61r Vv = \"O\"\\x20+\\x20\"\";\\x0d\\nfunct\\x69on\\x20V\\x723(Pz8){return Pz8;};var\\x20Vj = \"D\" + \"\";\\r\\nvar Oe3\\x" ascii
    $s19 = "F\\x634 + \\x59j0]();\\r\\n  \\x20 WHy0[Dk + (function CUl0(){re\\x74urn JPu;}()) +\\x20(function XI\\x668(){return JG\\x70\\x32" ascii
    $s20 = "09\\x41Rt[NAe0 + PJh\\x20+ MT\\x6a4]=1 \\x2a 0;\\r\\n\\t\\tARt[\\x28function AMj0(){return \\x4eh8;}()\\x29 + Fa0 + ASj](RJp2, Y" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}