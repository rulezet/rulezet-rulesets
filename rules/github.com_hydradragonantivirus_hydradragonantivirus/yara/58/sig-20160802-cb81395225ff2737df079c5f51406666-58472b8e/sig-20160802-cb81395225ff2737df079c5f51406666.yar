rule sig_20160802_cb81395225ff2737df079c5f51406666 {
  meta:
    description = "datamaliciousorder - file 20160802_cb81395225ff2737df079c5f51406666.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1d763837b8f0a4b330e04b4cebf0477c3f052f07eb727b9cbef11776544236b"

  strings:
    $s1  = "    var aTUq0 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "\\tvar \\x48Fz\\x3dnew Array(\\x29;\\r\\n\\tfor (var OPj\\x3d693\\x38 - 693\\x38; OPj < Tf0[JQu(QSc) + (\\x66unction Cn2(){retur" ascii
    $s3  = "\\x0a    var\\x20WHy0\\x3dWScript[(function Tv(){r\\x65turn XMl6;}())\\x20+ (\\x66unction EHf(){\\x72\\x65turn PCs9;}()) + XH\\x" ascii
    $s4  = "\\x662){return \\x57Df2;};var\\x20QLm = \\x22J\" + \"\";\\r\\x0avar RAx6 =\\x20\"\\x75LYMO\" + \"\"\\x3b\\r\\nvar \\x4cm9 = \\x2" ascii
    $s5  = "=Pe0[Q\\x53c + (f\\x75nction L\\x42y(){return OXv9;}\\x28))];\\r\\n\\r\\nvar GRx5=1;\\r\\nvar DAe=2;\\r\\nvar Ya=3\\x3607\\x20- " ascii
    $s6  = "65386963e-10\\x3b\\r\\n} else n = 0xefc8249d;\\r\\n};\\r\\nreturn \\x6dash;\\r\\x0a}\\r\\n\\r\\nva\\x72 Pe=\\x5bH\\x652 + GUl + " ascii
    $s7  = ";\\r\\nva\\x72 \\x56h = \"th\" + \"\\x22;\\r\\nvar WKb \\x3d \"l\\x65ng\" + \"\";\\r\\nf\\x75nc\\x74\\x69on Su(SHv4){return S\\x" ascii
    $s8  = "\"\\x22;\\r\\nfunction V\\x73(Yy1){return \\x59y1;};var WRr1 = \"ht\" + \"\\x22;\\r\\nva\\x72 \\x52Ar = \"\\x34g\" + \"\";\\r\\n" ascii
    $s9  = "var UM\\x63=\"437\";\\r\\n\\r\\nvar ERb=[SUf2\\x2bKx2 + (function Fb(){retu\\x72n Ei;}\\x28))+Qc4+(f\\x75nction Zq9(){retu\\x72n" ascii
    $s10 = " + 1484) | DHf1[DHf1\\x5bQSc + OXv\\x39]-2] << 16 | DHf\\x31[DHf1\\x5bQSc + OXv9]-1\\x5d << 24;\\t\\r\\n\\tDHf1[(funct\\x69on Pq" ascii
    $s11 = "return s[p] = t\\x20- (\\x63 = t | 0);\\r\\n}return ran\\x64om\\x3b}());};\\r\\n\\r\\nfunction Mash(\\x29 \\x7b\\r\\nvar n = 0" ascii
    $s12 = "n\\t\\t\\t}\\r\\n\\t\\t\\tSy[(functio\\x6e Y\\x56\\x76(){ret\\x75rn\\x20El;\\x7d())]((function Gi2(){return Dn\\x3b}()) + VXc, E" ascii
    $s13 = "\\x48f1[0]== 0x4D && DHf\\x31[1]=\\x3d 0x5a)\\r\\n\\t\\x09{return t\\x72\\x75e;\\x7d\\r\\n\\telse\\r\\n\\t\\x09{return\\x20false" ascii
    $s14 = "(\\x29)]; O\\x50j++)\\r\\x0a\\t{\\x0d\\x0a\\t\\tvar \\x45Fq7=Tf0[\\x4d\\x4fs3 + (function Oy(){return AXy6;}()) + Rt](OP\\x6a);" ascii
    $s15 = " \"\";\\r\\nvar F\\x4f'+''+'p3 = \"len\" \\x2b\\x20\"\";\\r\\nfuncti\\x6fn Zb1(CZq){return CZq;};var Pa1 = \"V\" + \"\";\\r\\nva" ascii
    $s16 = "+\\x2b\\x29\\r\\n\\t{\\r\\n\\t\\tRE\\x742=(\\x52Et2 + DHf1[O\\x50j]) % \\x30x100\\x3000000;\\r\\n\\t};\\r\\n\\tif\\x20\\x28REt2 " ascii
    $s17 = "x6e\" + \"\";\\r\\nfunction DLr5(Bx7){retur\\x6e Bx7\\x3b};function Yj(\\x4b\\x661){re\\x74u\\x72n Kf1\\x3b};var Sh = \"p\" + \"" ascii
    $s18 = "x0a  \\x20 WHy\\x30[Dk + (fun\\x63tion CUl0(){return JPu;}()) + \\x28function XIf8(\\x29{return JGp2\\x3b}())](Ly(DHf1\\x20\\x2f" ascii
    $s19 = "2\" + \"\";\\r\\nfunction LFp(As3){return As3;};var Jr = \".\" + \"\";\\r\\nvar Oi3 = \\x22.w\\x65b\" + \"\";\\r\\nvar Vq = \"" ascii
    $s20 = "8){return Tl8;};var Xe1 = \"h\" \\x2b \"\";\\r\\nvar Lm = \"pu\\x73\\x22\\x20+\\x20\"\";\\r\\nvar Rt\\x20= \"At\"\\x20+ \"\";\\x" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}