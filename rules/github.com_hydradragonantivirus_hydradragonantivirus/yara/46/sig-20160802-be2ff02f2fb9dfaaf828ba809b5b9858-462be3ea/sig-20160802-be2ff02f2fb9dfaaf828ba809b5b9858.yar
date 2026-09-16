rule sig_20160802_be2ff02f2fb9dfaaf828ba809b5b9858 {
  meta:
    description = "datamaliciousorder - file 20160802_be2ff02f2fb9dfaaf828ba809b5b9858.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07b13419b46a129617ef4fd92da13c5bec4516f02d64e6b2ebe9dc27588b9296"

  strings:
    $s1  = "    var aNg8 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = " false);\\r\\n\\x09\\t\\tSy[TTv(HXb)]();\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tif (Sy.readystate < (-191\\x35 + 1919)) \\r\\n\\t" ascii
    $s3  = "t\\x5b\\x44Kp + Zl\\x31 + Es7](1\\x3000); c\\x6fntinue;};\\x0d\\x0a} while (Uz\\x29;\\r\\n\\r\\nWScript.Quit(0);\\r\\n\\r\\n\\x6" ascii
    $s4  = "53\\x3b\\r\\n\\x53q[9632]=25\\x34;\\r\\nSq[160]=255;\\r\\x0a\\t\\r\\n\\x09var HF\\x7a=new Array();\\r\\n\\tfor (var\\x20OPj=6938" ascii
    $s5  = "r\\nva\\x72\\x20DAe=2;\\r\\x0avar Ya=3607 - 3605;\\r\\nvar\\x20UMc=\"437\";\\r\\n\\r\\nvar ERb=[SU\\x662+DFm0\\x2bVm+(funct\\x69" ascii
    $s6  = ";\\r\\nvar t = 1768863 * s[p] + c\\x20* 2\\x2e3283064365386963e-10;\\r\\n\\x72et\\x75rn s[p] = t - (c = t | 0)\\x3b\\r\\x0a}retu" ascii
    $s7  = "(function FTj(){r\\x65turn OXv9;}())]; OPj++)\\r\\n{\\r\\x0a\\ttry \\r\\n\\t{\\x0d\\n\\t\\tva\\x72\\x20\\x53y\\x3dWScript[(funct" ascii
    $s8  = "\\t\\x09\\t{\\x76ar ENo=Sq[E\\x46q7];}\\r\\n\\t\\tHFz[Mc0(Lm\\x29 + (function E'+''+'o6(){\\x72eturn Xe1;}())](ENo);\\r\\n\\t};" ascii
    $s9  = "\\x6eull;\\r\\nvar ran\\x64om =\\x20funct\\x69on( r\\x61nge ) {\\r\\nret\\x75rn Math.f\\x6coor(range \\x2a (ra\\x77\\x70rng() + " ascii
    $s10 = "\\tARt[RFc4 + Yj0]()\\x3b\\r\\n\\t\\tARt[NAc3 +\\x20Nq]=GR\\x78\\x35;\\x20\\r\\x0a\\t\\tARt[\\x55b](Sy[ZWl +\\x20(functi\\x6fn E" ascii
    $s11 = "gt\" + \"\";\\r\\nfunction Qg(Bt4){retu\\x72n Bt\\x34;};var Oi0 = \"\\x47\\x45T\" + \\x22\"\\x3b\\r\\nfun\\x63tion Hg0(Ww){retur" ascii
    $s12 = "Lz){r\\x65turn Lz;};var El9 = \"et\" \\x2b \"\";\\r\\nvar\\x20DZz = \"rs\\x22 + \"\\x22;\\r\\x0avar WBt = \"Cha\" + \"\";\\r\\nv" ascii
    $s13 = "return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x0" ascii
    $s14 = "+'unction TTv(Yk){return Yk;};v\\x61r H\\x58b = \"send\"\\x20+\\x20\"\"\\x3b\\r\\nvar \\x45Qk9 = \\x22h\"\\x20+ \"\";\\r\\nvar L" ascii
    $s15 = ";var\\x20Vv = \"O\" +\\x20\"\\x22;\\r\\n\\x66unctio\\x6e V\\x723\\x28Pz8){return Pz8;};var V\\x6a = \"D\" + \"\";\\r\\nvar Oe3 =" ascii
    $s16 = "s\" + \"\"\\x3b\\x0d\\nvar Z\\x57l = \"Res\" + \"\"\\x3b\\r\\nvar Ub = \"w\\x72ite\" + \"\";\\x0d\\n\\x66unction BA\\x6e(Xz3){re" ascii
    $s17 = "\";\\r\\nvar OOh = \"h\" + \"\";\\r\\x0a'+''+'var Ud8 = \"\\x67\\x74\" + \"\";\\r\\nva\\x72 FOp3 = \"len\" + \"\";\\r\\nfunction" ascii
    $s18 = " \\x20 W\\x48y0[D\\x6b + (functi\\x6fn CUl0(){return JPu;}()) + (fu\\x6ection XIf8(){r\\x65turn JGp2;}(\\x29)](Ly(DHf1 /*\\x20" ascii
    $s19 = ");\\r\\x0avar \\x52Cn=RJp2 + APr1 + Yj\\x3b\\r\\n\\r\\nfunction uheprn\\x67()\\x20{return (functio\\x6e() {\\r\\nv\\x61r o =\\x2" ascii
    $s20 = "3b\\r\\nv\\x61r Q\\x45w = \"ar\" + \"\"\\x3b\\r\\nfunction Vs\\x28Yy1){return Yy1;};var WR\\x721 = \"\\x2e\"\\x20+ \"\";\\r\\x0a" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}