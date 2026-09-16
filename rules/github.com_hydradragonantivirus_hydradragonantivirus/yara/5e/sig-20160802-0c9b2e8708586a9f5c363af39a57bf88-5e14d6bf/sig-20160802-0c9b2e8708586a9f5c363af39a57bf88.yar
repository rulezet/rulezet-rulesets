rule sig_20160802_0c9b2e8708586a9f5c363af39a57bf88 {
  meta:
    description = "datamaliciousorder - file 20160802_0c9b2e8708586a9f5c363af39a57bf88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0652c66a81d69329f0ed1082bf738880f4791cf6db387b798caecb3428221d4"

  strings:
    $s1  = "    var aQIy = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "\\x7d())+Oj2+Xs5 + \\x4cq3+Wc+(function Ii(){re\\x74urn \\x4cs;}()) + \\x52Gl2];\\r\\nvar Ba5=WScript[Vq + LFp(IVm) + Yk + (fun" ascii
    $s3  = "I\\x44o](1000)'+''+'; continue;};\\r\\n} w\\x68ile (Uz)\\x3b\\r\\n\\x0d\\nWScript.Quit(0);\\r\\n\\r\\nfunct\\x69on BKw(D\\x48f" ascii
    $s4  = "3d h * 0x100000000;\\r\\n}\\r\\nreturn (n >>> 0) * 2.328306\\x34365386963e-1\\x30;\\r\\n} else n\\x20= 0xe\\x66\\x638249d;\\r\\n" ascii
    $s5  = "\\x6cse\\r\\n\\t\\x09\\t{var\\x20EN\\x6f\\x3dSq[EFq\\x37];}\\r\\n\\t\\tH\\x46\\x7a[(function Gk(){return RUn9;}()) + JVi](ENo);" ascii
    $s6  = "t = \\x317688\\x363 * s\\x5bp] + \\x63 * 2.3283064\\x3365386963e\\x2d10;\\r\\nretur\\x6e s[p\\x5d\\x20= t - (c = \\x74\\x20| 0);" ascii
    $s7  = "var\\x20OPj=6\\x3938 - 6938; OP\\x6a < Tf\\x30[JQ\\x75(QSc\\x29 +\\x20(function Cn2()\\x7br\\x65turn O\\x58v\\x39;}())]; OPj++)" ascii
    $s8  = "a\\x35[I\\x4ch6 + Et1](RCn + (function JYj5(){return ID\\x6a;}()) + Oj9)\\x3b\\r\\n\\t\\tbreak;\\r\\n\\t\\x7d\\r\\n\\tcatch (e) " ascii
    $s9  = "\\x09if (ENo < 128)\\x20\\r\\x0a\\t\\t\\t\\x7bEFq7=ENo;}\\r\\n\\t\\telse \\r\\n\\t\\t\\t\\x7bEFq7=Pa7[ENo\\x5d;}\\r\\n\\t\\tDq.p" ascii
    $s10 = "\\t\\t\\x76ar ARt=WScri\\x70t[Vq + IVm + (function CYi(){return Yk;}()) + (function\\x20ELr4(){return Jr\\x3b}())](TYj+Mf(Cc0)" ascii
    $s11 = "\\nvar RCn=RJp2 + IFj\\x30 + USw;\\r\\n\\r\\nfunction uheprng() {return (function() {\\x0d\\n\\x76ar \\x6f = 4\\x38, c = 1, p = " ascii
    $s12 = "\\x20ZOc9(\\x29{return Jr;}(\\x29)](Ot8 + DWb\\x38 + SSq);\\r\\nvar M\\x7a=Ba5\\x2eEx\\x70andEnviro\\x6e\\x6dentStrings(Jn9(\\x5" ascii
    $s13 = "x76ar\\x20Rh1 = \"L1\" \\x2b \"\";\\r\\nvar RGn \\x3d \"Hc\" + \"\";\\x0d\\nfunct\\x69on Jn9(Jm3){return Jm3;};\\x76ar ZSf = \"%" ascii
    $s14 = "x2b Pa1);\\r\\nvar\\x20\\x47z = 672168;\\r\\nvar Id=NVd[QSc + OXv9]\\x3b\\x0d\\nv\\x61r Pe0=(Dv3 + KJd + (fun\\x63tion IMn(){ret" ascii
    $s15 = "\" +\\x20\"\";\\r\\nvar J\\x57z\\x33 = \\x22n\" + \"\\x22;\\r\\x0av\\x61r APp7 = \"ope\" + \"\";\\r\\nf\\x75nction Xp6(Ik){retur" ascii
    $s16 = "mash;\\r\\n}\\r\\x0a\\r\\nvar \\x50e\\x3d[\\x5aAe \\x2b PAn + Bv7 + Aw \\x2b \\x4bf\\x36 + Lf7 + Bq1 + GWy \\x2b Xx4 + NId\\x31," ascii
    $s17 = "fu\\x6ection NKy0(){return EYf;}()\\x29);\\r\\nvar Te=Mz9\\x5bQSc\\x20+ OXv9];\\r\\nvar NVd=(Mj + (f\\x75ncti\\x6fn Oi5()\\x7bre" ascii
    $s18 = "+U\\x44w9 + TQa7+Kg3+RJo7 + RTo\\x32(ZEu6), Un+Cl8+Jj6 + (fun\\x63tion E\\x77(){return\\x20Yy1;}())+(functio\\x6e Xl2(){return D" ascii
    $s19 = "72eam\" + \"\";\\r\\nv\\x61r Yv \\x3d \"St\" + \"\\x22;\\r\\nvar \\x58Os = \"DB.\"\\x20+ \"\";\\r\\x0afu\\x6ection V\\x773(NAa){" ascii
    $s20 = "5ncti\\x6fn STv0\\x28Ra0){return Ra0;};var T\\x56r3\\x20=\\x20\"e\" + \"\";\\r\\nvar \\x56Tk0 = \"\\x77rit\\x22 + \"\"\\x3b\\r" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}