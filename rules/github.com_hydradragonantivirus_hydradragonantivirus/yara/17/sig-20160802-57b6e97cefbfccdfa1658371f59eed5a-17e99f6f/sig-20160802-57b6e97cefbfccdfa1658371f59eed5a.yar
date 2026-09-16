rule sig_20160802_57b6e97cefbfccdfa1658371f59eed5a {
  meta:
    description = "datamaliciousorder - file 20160802_57b6e97cefbfccdfa1658371f59eed5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d20145fd6edb4806ba9fd71e12e9a1ad4012580796b5a04c218b5f011ee841a"

  strings:
    $s1  = "    var aGJv = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "\\tco\\x6etinue;\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tv\\x61r\\x20A\\x52t=WScript[F\\x77 + Mh + Yd\\x36 + CYi + (fu\\x6ec\\x74ion" ascii
    $s3  = "x5af+Hh+VUg + RUf\\x2bCp + IHt+(function Wc6(\\x29{ret\\x75rn Pu9;}(\\x29)];\\r\\nvar Ba5=WScript[Fw + Mh + Yd6 + CYi + DBs6]\\x" ascii
    $s4  = " * 0x100000000;\\r\\n}\\r\\nreturn (n >>> 0) * 2.3283064\\x3365386963e-10\\x3b\\r\\n} else n \\x3d 0xef\\x63\\x38249d;\\r\\n};" ascii
    $s5  = "0[\\x51Sc +\\x20(function LBy(){return OXv9;\\x7d())];\\r\\n\\r\\nvar GRx5=1;\\r\\x0a\\x76\\x61r DAe=2;\\r\\nvar Ya=3607 - 3605;" ascii
    $s6  = " 1\\x376886\\x33 * s[\\x70] + c\\x20* 2.32830643\\x365386963e-\\x310;\\r\\nreturn\\x20s[p]\\x20\\x3d t - (c = t\\x20\\x7c 0);\\r" ascii
    $s7  = "\\r\\nfu\\x6ection VOy7(DHf1 /* L\\x20 */)\\r\\n{\\r\\x0a\\ti\\x66 (DHf1[\\x30]\\x3d= 0\\x784D && DHf1[1]== 0x5a)\\r\\n\\t\\t{re" ascii
    $s8  = "\\x4cr){return \\x4cr\\x3b};f\\x75nction\\x20Xp\\x36(\\x49k){return Ik;};var Fu3 \\x3d \"O\" + \"\";\\r\\nfunction Vw\\x33(NAa){" ascii
    $s9  = "\\x20GNn(){\\x72eturn \\x46Ys1;}())\\x2bRj3(Sj5)+WSb0+(fu\\x6ection Ry0(){return Qq;}()), Kx2(SUf2)+Kg3\\x2bQR\\x795 + ZZ\\x73" ascii
    $s10 = "\\n\\ttry \\r\\n\\t{\\x0d\\n\\x09\\x09var \\x53\\x79=W\\x53cript[(function \\x57c(){return Fw;\\x7d()) + Mh +\\x20Yd6 + CY\\x69 " ascii
    $s11 = "n Er8;};functi\\x6fn R\\x56y(Mb0){return Mb0;};\\x76a\\x72 \\x5aVt\\x37 = \"l\\x65\" + \\x22\";\\r\\nvar LW\\x72 = \"oFi\" + \"" ascii
    $s12 = "= \"eT\" + \"\";\\r\\nvar Fy = \"Sav\" + \"\";\\r\\nf\\x75nction Nq(\\x4fBj){return \\x4fBj\\x3b};funct\\x69o\\x6e ETx9(ZZc8){re" ascii
    $s13 = ";\\r\\x0ava\\x72 YDx4 = \"t.\\x22 + \"\";\\r\\nvar Rn\\x20= \"ip\" + \"\"\\x3b\\r\\nvar \\x53Wb = \"WScr\" + \"\";\\r\\nfuncti" ascii
    $s14 = "tif (ENo < 128) \\r\\n\\t\\t\\t{EF\\x717=E\\x4eo;}\\r\\n\\t\\te\\x6cse \\r\\n\\t\\t\\t{EFq\\x37=Pa7[ENo];}\\x0d\\n\\t\\tDq.\\x70" ascii
    $s15 = "a\\x72 Vh = \"th\\x22 + \"\";\\r\\nvar \\x57K\\x62 = \"leng\" + \"\";\\r\\nfun\\x63tio\\x6e Su(SHv4){return SH\\x764;};var Xt6 " ascii
    $s16 = "x5d;\\x0d\\nvar Pe0=(D\\x76\\x33 + KJd + (function IMn(){return CZi\\x38\\x3b}(\\x29), Zs5 + Te1 + Su(MSl) \\x2b Xt6);\\r\\nvar " ascii
    $s17 = "x3b};fu\\x6ection \\x53Gv(KL\\x795){return\\x20KLy5;};func\\x74i\\x6fn JQu\\x28KK\\x684){return \\x4bKh\\x34;}\\x3bvar OXv9 = \"" ascii
    $s18 = "nvar Gr4 = \"/a\" + \"\";\\r\\nfunction TNk4(Xs5){return Xs5;};var Xl2 = \":/\" + \"\"\\x3b\\r\\n\\x76ar MHr = \"tp\" + \"\";\\r" ascii
    $s19 = "6;}(\\x29)](MVd1(Qg)+\\x57t6+Fu3+RDj + PIs6 + Wz3);\\r\\n\\t\\tARt[Pc0]();\\r\\n\\t\\tARt[(functi\\x6fn Cb(){return TG\\x619;}()" ascii
    $s20 = "nction C\\x6e2(){return OXv9;}())]; OPj++)\\r\\n\\t{\\x0d\\n\\t\\tvar \\x45\\x46q7=Tf0[SMe3 + Ec9 + \\x4ba\\x5d\\x28OPj);\\r\\n" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}