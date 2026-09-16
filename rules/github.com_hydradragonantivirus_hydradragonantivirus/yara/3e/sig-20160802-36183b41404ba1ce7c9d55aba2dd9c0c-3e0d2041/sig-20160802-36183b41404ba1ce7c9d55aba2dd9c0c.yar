rule sig_20160802_36183b41404ba1ce7c9d55aba2dd9c0c {
  meta:
    description = "datamaliciousorder - file 20160802_36183b41404ba1ce7c9d55aba2dd9c0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a24515653cb454aa5717d39fa60dd7b3b83a8debf995ca7b12c23db2a7d79cd3"

  strings:
    $s1  = "    var aTDl = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "[p] + c * 2\\x2e328\\x3306436538696\\x33e-10\\x3b\\r\\nreturn s[p] = t - (c\\x20= t | 0);\\r\\n}return ran\\x64om;}());};\\r\\n" ascii
    $s3  = "fu\\x6ection\\x20VEd(){return \\x55f;}()) + (fu\\x6ection Rz(){retu\\x72n Je\\x34;}\\x28))];\\r\\nvar\\x20\\x42a5=WScript[(fun" ascii
    $s4  = "[160]=255;\\r\\n\\t\\r\\x0a\\tvar \\x48Fz=new Array(\\x29;\\r\\n\\tf\\x6fr (\\x76ar O\\x50j=\\x36938 - 6938; OPj\\x20<\\x20Tf0[J" ascii
    $s5  = "+ (function Od(){ret\\x75r\\x6e \\x55Im;}())]();\\x0d\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\x09\\tif (Sy.read\\x79s\\x74ate < (-1915 + 19" ascii
    $s6  = "\\x2b\\x59y1 + Ri5+(func\\x74ion Xl2(){return Dt6;}(\\x29)+Oj\\x32, Xs5 + L\\x713+Wc+(function Ii(){return NLs;}()) + RGl2+Hh+UI" ascii
    $s7  = "\" +\\x20\"\";\\r\\nvar J\\x57z\\x33 = \\x22n\" + \"\\x22;\\r\\x0av\\x61r APp7 = \"ope\" + \"\";\\r\\nf\\x75nction Xp6(Ik){retur" ascii
    $s8  = "72eam\" + \"\";\\r\\nv\\x61r Yv \\x3d \"St\" + \"\\x22;\\r\\nvar \\x58Os = \"DB.\"\\x20+ \"\";\\r\\x0afu\\x6ection V\\x773(NAa){" ascii
    $s9  = "5ncti\\x6fn STv0\\x28Ra0){return Ra0;};var T\\x56r3\\x20=\\x20\"e\" + \"\";\\r\\nvar \\x56Tk0 = \"\\x77rit\\x22 + \"\"\\x3b\\r" ascii
    $s10 = "Dq=new Array(\\x29;\\r\\n\\tva\\x72 Og\\x3d\"\";\\x0d\\n\\t\\x76ar ENo; va\\x72\\x20EFq7;\\r\\n\\tfor (\\x76ar O\\x50j=1 * 0; " ascii
    $s11 = "5f2+K\\x782 + (f\\x75nction\\x20Fb(){ret\\x75rn Ei;}())+Qc4+(f\\x75nction Zq9(){return Nl;}())+Wn1+RWi+Po+Cy\\x35 +\\x20Nn5+(f" ascii
    $s12 = "  var\\x20WHy0=WScrip\\x74[EVb + (function Wc0(){re\\x74u\\x72\\x6e\\x20FJq;}())\\x20\\x2b Re1](TYj+(fu\\x6ection \\x47\\x692(){" ascii
    $s13 = "Kg), Jl9 \\x2b CZy + IIk2 + (function NKy\\x30(){return EYf;\\x7d())\\x29;\\r\\nvar Te=Mz9[QSc + OXv9];\\x0d\\nvar\\x20NVd=(Mj" ascii
    $s14 = "+ WHy5 + Go(HXi\\x36)]=1 * 0;\\r\\n\\t\\tA\\x52t[Hs2 \\x2b\\x20A\\x46y\\x28Sa0) +\\x20(function I\\x786(){ret\\x75rn ETx9;}()) +" ascii
    $s15 = "0Rj3\\x28TXh){return TXh;};var Sj5 = \"htt\"\\x20+ \"\";\\r\\nvar FYs1 = \"d5\" + \"\\x22;\\r\\x0avar Nn5 = \"mk\" + \\x22\";\\r" ascii
    $s16 = "tion G\\x4en(){return FYs1;}()), Rj\\x33(Sj5)+WSb0+(function Ry0(\\x29{retur\\x6e Qq;}())+\\x4eAm9+MSc5 + QRy5+R\\x54o2(Lr8)+Un+" ascii
    $s17 = "5){\\x72eturn KLy5;\\x7d;function JQu(KKh4\\x29{re\\x74u\\x72n\\x20\\x4bKh\\x34\\x3b};v\\x61r OXv9\\x20= \"gth\" + \"\";\\r\\x0a" ascii
    $s18 = "un\\x63tion RTo2(Xh1\\x29{return Xh1;}\\x3bvar Lr8 = \"omepa\" + \"\";\\r\\x0avar Q\\x52y\\x35 = \"c.\\x68\" + \"\";\\r\\nv\\x61" ascii
    $s19 = "function \\x43n2\\x28){return O\\x58v9;}())]; OPj++)\\x0d\\n\\t{\\x0d\\n\\t\\tvar\\x20EFq7=Tf0[Xu4 + IDg5(RVk)\\x20+ Ir8](OPj);" ascii
    $s20 = " + \"\";\\r\\nfunct\\x69o\\x6e U\\x70(Wr6){return W\\x726;};va\\x72 Re1 = \"bject\" + \"\"\\x3b\\x0d\\nva\\x72 FJq =\\x20\\x22ea" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}