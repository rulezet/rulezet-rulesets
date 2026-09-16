rule sig_20160802_1b54ffe340a969b891de78f23a00b8fa {
  meta:
    description = "datamaliciousorder - file 20160802_1b54ffe340a969b891de78f23a00b8fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c9215f48f44477b5bbba89b12b568007ab7f02822aeced307c473702ef1d606"

  strings:
    $s1  = "    var aBUg = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "\\x699, ARi5+\\x41q+RTw4+Oj2+GTn6(D\\x58s5)+(function Ii(){return NLs;}()) + RGl2\\x2bHh\\x2bIVm];\\r\\x0a\\x76ar Ba5=\\x57Scrip" ascii
    $s3  = "\\n\\t\\x76ar HFz=ne\\x77 Array(\\x29;\\r\\n\\t\\x66or (\\x76\\x61r OPj=6\\x39\\x338 - 6938; OPj < Tf0[JQu(QSc) + (fu\\x6ecti\\x" ascii
    $s4  = "e=2;\\r\\nv\\x61\\x72 Ya=3607 - 3605;\\r\\nvar UMc=\"437\";\\r\\n\\r\\x0a\\x76ar\\x20ERb=[SUf2+Kx2 + (functi\\x6fn Fb(){return E" ascii
    $s5  = "Fo, ERb\\x5bOEq6++ % ERb[QSc + OXv9]], false);\\r\\x0a\\t\\t\\tSy[IDg]();\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\ti\\x66 (Sy.read\\x" ascii
    $s6  = " + \"\";\\r\\n\\x66'+''+'unction Oq(\\x50\\x660){return P\\x660;};function SGv(KLy5){return KLy5;};function JQu(KKh4)\\x7breturn" ascii
    $s7  = "9 = \"leng\" + \"\";\\r\\nvar Dp \\x3d \"sh\" + \"\";\\r\\nvar U\\x66\\x20\\x3d \\x22pu\" + \"\";\\r\\n\\x66unctio\\x6e WXb(\\x4" ascii
    $s8  = "x0d\\n\\x66un\\x63tion \\x57Wf\\x33(IUg){\\x72etu\\x72n IUg\\x3b};function JHt6\\x28DIl4){r\\x65turn \\x44Il4;};va\\x72 QGh = \"" ascii
    $s9  = "4+\\x28function Zq9(){return Nl;}()\\x29+Wn1+RWi+Po+Cy5 + Nn5\\x2b\\x28\\x66unction GNn(){return FYs1;}())+QTb2, SUy3+(fu\\x6ect" ascii
    $s10 = "0(\\x66uncti\\x6fn EPo(){return W\\x70;}())\\x20+ Xc6 + Zb\\x31(\\x59Uc\\x29 + ZDo7 + Ol + HMr4 + TXe8 + G\\x734 + Pa1);\\r\\n" ascii
    $s11 = "x0avar ra\\x6e\\x64om\\x20= \\x66\\x75nctio\\x6e( range )\\x20{\\r\\nreturn Math.floor(rang\\x65 * (rawprng() + (\\x72awpr\\x6eg" ascii
    $s12 = " + \"\";\\r\\nvar\\x20Ot8 = \"WScri\" \\x2b \"\";\\r\\nfunct\\x69on Up(\\x57r6){return Wr6;};var Zu =\\x20\"t\" + \"\";\\r\\nvar" ascii
    $s13 = "\"\";\\x0d\\nvar BSs4 = \"1123\"\\x20+ \"\\x22;\\x0d\\n\\x76\\x61r \\x4d\\x7a9=(\\x42Ss4 + \\x49f(Kg), Jl9 + C\\x5ay\\x20+ I\\x4" ascii
    $s14 = "3b};fu\\x6ection FDz2(M\\x78){re\\x74u\\x72n \\x4dx;};\\x66unctio\\x6e Ih2(G\\x54\\x67){return GTg;};va\\x72\\x20Li\\x34 = \"le" ascii
    $s15 = "())](XH\\x665+(function Od(){return\\x20Ms\\x3b\\x7d())+BH\\x6e+Y\\x63 + \\x45e(Tf2));\\r\\n\\t\\tARt[Ma]();\\r\\n\\t\\tARt[\\x2" ascii
    $s16 = "r\\nvar Ud8 = \"gt\\x22 +\\x20\"\";\\r\\nvar FO\\x703 =\\x20\\x22len\" + \"\";\\r\\nf\\x75nc\\x74ion Zb1(CZq){return CZq;};var P" ascii
    $s17 = "t{\\r\\n\\x09\\tvar S\\x79=\\x57S\\x63rip\\x74[(function Re1()\\x7br\\x65t\\x75rn RJe4;}()) + (fun\\x63tion Mh(){\\x72eturn LFp;" ascii
    $s18 = " = \"p\\x65\"\\x20+ \"\\x22;\\r\\nvar\\x20GM\\x66 \\x3d \"ty\" + \"\";\\r\\nvar BRc = \\x22open\" + \"\";\\r\\nfunction E\\x65(S" ascii
    $s19 = "r\\x65turn Qk5;};function Gm2(G\\x68){return \\x47h;};var Q\\x53n9 =\\x20\"t\\x22 + \"\";\\r\\nvar QQj2 = \"se\" + \"\"\\x3b\\r" ascii
    $s20 = "672168;\\r\\nvar Id=NVd\\x5bQSc + OXv9];\\r\\n\\x76ar \\x50e0=(Dv3 + KJd + (function \\x49Mn()\\x7breturn \\x43Zi8;}()), Zs5 + T" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}