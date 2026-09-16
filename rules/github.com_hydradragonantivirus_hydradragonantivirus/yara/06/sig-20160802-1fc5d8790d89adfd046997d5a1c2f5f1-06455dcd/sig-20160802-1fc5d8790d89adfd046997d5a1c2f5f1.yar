rule sig_20160802_1fc5d8790d89adfd046997d5a1c2f5f1 {
  meta:
    description = "datamaliciousorder - file 20160802_1fc5d8790d89adfd046997d5a1c2f5f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a3167258cc6061ab145a1eaac369ff84406ab3d4a6a72642a5f3284b55ff122"

  strings:
    $s1  = "    var aINe = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "+ Re1+Bb5(GHx)\\x5d;\\r\\nvar Ba5=WScript[Wc0 + (function PXo9(){return EI\\x6b;\\x7d())\\x20+ YF\\x65 + (function SS\\x71(){ret" ascii
    $s3  = "ngt\" + \"\";\\r\\nfunction Qg(Bt4){\\x72etur\\x6e Bt4;};var Oi0\\x20\\x3d \"GET\\x22 \\x2b \"\";\\r\\x0afunction Hg0(Ww){return" ascii
    $s4  = "3d3607 - 3605;\\r\\nvar UMc=\"4\\x337\";\\r\\n\\r\\nvar ERb=[SUf2+Kx2 \\x2b (func\\x74ion Fb(){\\x72eturn Ei;}())+Qc4\\x2b(funct" ascii
    $s5  = "]], false);\\r\\n\\t\\t\\tSy[TTv(HXb)]();\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\x09if (Sy.readystat\\x65 < (-1915 + 1919)\\x29 \\r" ascii
    $s6  = "22.She\" + \"\\x22;\\x0d\\nvar Qk1 = \"c\\x72ipt\" + \"\";\\r\\x0avar Zk = \"WS\" + \"\";\\r\\nfu\\x6ection BZb(YSa){return YSa;" ascii
    $s7  = "\\x72 Vv = \"O\" \\x2b \\x22\";\\r\\x0afuncti\\x6fn \\x56r\\x33(Pz8){return Pz8;};var \\x56j = \"D\" + \"\";\\r\\nvar Oe3 \\x3d " ascii
    $s8  = "DH\\x661 /* y  */)\\r\\n{\\r\\n    var \\x57Hy0=WScript[BZ\\x62(Wc\\x30) + PMq2(EIk) \\x2b\\x20YFe + (function Tv(\\x29{ret\\x75" ascii
    $s9  = "\\r\\n\\r\\nfor (var OPj=0;\\x20OPj < Pe[\\x51Sc + \\x28\\x66\\x75n\\x63tion FTj(){return OXv9;}())]; \\x4fPj\\x2b\\x2b)\\r\\n{" ascii
    $s10 = "Lz){r\\x65turn Lz;};var El9 = \"et\" \\x2b \"\";\\r\\nvar\\x20DZz = \"rs\\x22 + \"\\x22;\\r\\x0avar WBt = \"Cha\" + \"\";\\r\\nv" ascii
    $s11 = "return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x0" ascii
    $s12 = "Hu8\\x3b}())](\\x28\\x66un\\x63ti\\x6f\\x6e GOk(\\x29{return Z\\x6b;}()) + Qk1 + UJl + ZYi);\\x0d\\nvar Mz=Ba5.Expan\\x64Envi\\x" ascii
    $s13 = "lll\" + \"\";\\x0d\\nfunction Oq(Pf0){return Pf0;};function \\x53Gv(KLy5){retur\\x6e KLy5;};function JQu(KKh4){ret\\x75rn KK\\x6" ascii
    $s14 = "x58t6);\\r\\n\\x76ar UWy4=\\x50e0[QSc + (functio\\x6e LBy(){return OXv9;}())];\\r\\n\\r\\nvar GRx5=1;\\r\\x0ava\\x72 DAe=2\\x3b" ascii
    $s15 = "= \"4z\" + \"\";\\r\\nfunction Je4(LFp){return LFp;};function KQd9(ZO\\x639)\\x7breturn ZOc9;};var Yk\\x20\\x3d \"qk\\x22 + \"\"" ascii
    $s16 = "r\\n\\t\\tAR\\x74[NAe\\x30 + PJ\\x68 + MTj4]=1 \\x2a 0;\\r\\n\\t\\tARt[(function AM\\x6a0(){re\\x74urn Nh8;}()) + Fa0 + ASj](RJp" ascii
    $s17 = "function TTv(Yk0){return Yk0\\x3b};v\\x61r HXb = \"s\\x65n\\x64\" \\x2b \"\";\\r\\n\\x76ar EQk\\x39 =\\x20\"h\" + \"\";\\r\\nva" ascii
    $s18 = "[\\x70]\\x20= t\\x20- (c = \\x74 | \\x30)\\x3b\\r\\n\\x7dreturn random;}());};\\r\\n\\r\\nfunct\\x69on M\\x61sh() {\\x0d\\nv\\x6" ascii
    $s19 = "+ \"\\x22\\x3b\\r\\nvar \\x5aWl = \"Res\" + \"\\x22;\\r\\nvar Ub = \"\\x77rite\" + \"\"\\x3b\\r\\x0afunction B\\x41n(Xz3){return" ascii
    $s20 = "{return \\x51x\\x3b};\\x76ar JHu8 = \"ect\\x22 + \"\";\\x0d\\nvar YFe = \"bj\" + \"\\x22\\x3b\\r\\nv\\x61r EIk \\x3d\\x20\"teO\"" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}