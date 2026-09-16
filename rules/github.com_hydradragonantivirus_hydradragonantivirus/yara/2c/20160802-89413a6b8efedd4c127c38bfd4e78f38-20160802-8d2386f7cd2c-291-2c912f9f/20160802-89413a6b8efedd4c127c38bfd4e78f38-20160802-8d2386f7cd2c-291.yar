rule _20160802_89413a6b8efedd4c127c38bfd4e78f38_20160802_8d2386f7cd2c_291 {
  meta:
    description = "datamaliciousorder - from files 20160802_89413a6b8efedd4c127c38bfd4e78f38.js, 20160802_8d2386f7cd2c8ade2d65350b53722cbc.js, 20160802_ee2839601907846df1380b0738e515ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da1f3ce75fe404d2a90591c3272a2bbf79221e5b49790bbce6ef4f1c6b7572ae"
    hash2       = "cb981c4a5bbb74592ef414f6e026630632d93d57d553ec7e24f668c23417f0f8"
    hash3       = "adce6bae397465621c2dbf4b7310cf1281aaeb7aeeaa6aa3f9798687de59e9b0"

  strings:
    $s1  = "65386963e-10;\\x0d\\nre\\x74urn s[p] = \\x74 - (\\x63 = t | 0);\\r\\n}return ra\\x6edom;}());};\\r\\n\\r\\nfunctio\\x6e Mash() {" ascii
    $s2  = "\\nvar FOp3 = \"len\" + \\x22\";\\r\\x0afunction Zb1(CZq\\x29{return CZq;};var\\x20Pa1 = \\x22l\" \\x2b \\x22\";\\r\\nva\\x72 Gs" ascii
    $s3  = "Nk4(Xl2\\x29\\x2b(function RGl2\\x28){return Gr4;}()) + (fu\\x6ectio\\x6e Ii(){ret\\x75rn TEd;}()) + Zf+Hh+VUg + RUf+(function I" ascii
    $s4  = "7d()) + Hp\\x34\\x20+ B\\x5a\\x62\\x28\\x57M\\x70)\\x29;\\x0d\\nvar Mz\\x3dBa5.\\x45xpandEnv\\x69ron\\x6dentStrings(Mq2\\x20+ Qx" ascii
    $s5  = "6436538696\\x33e-10;\\r\\x0a}\\x20e\\x6cse \\x6e = 0xefc8249d;\\r\\n\\x7d;\\x0d\\n\\x72eturn mash;\\r\\n}\\r\\n\\r\\nv\\x61r Pe=" ascii
    $s6  = "x48f(){return Wb8;}()));\\r\\n\\x76ar RJp2=Mz + Ft + Pz + YWf + FGa;\\r\\nvar RCn=RJp2 + Z\\x61 \\x2b US\\x77;\\r\\n\\r\\x0afunc" ascii
    $s7  = "d6){return Yd6;};\\x66u\\x6ect\\x69on Up(Wr6){ret\\x75rn Wr6\\x3b};var AHa = \"bject\"\\x20\\x2b \"\"\\x3b\\r\\nvar \\x47\\x43o " ascii
    $s8  = " G\\x6f(HXi6)]=1 * 0;\\x0d\\n\\t\\tARt\\x5b\\x48s\\x32 \\x2b AFy(S\\x610) + (funct\\x69on Ix6(\\x29{return ETx9;}()) +\\x20ZZc8]" ascii
    $s9  = "){return Yy1;};var WRr'+''+'1 =\\x20\"\\x65\" + \"\";\\r\\x0avar NJa = \"/sit\" + \\x22\";\\r\\nvar \\x50Xh1 = \"\\x74p:/\" + \"" ascii
    $s10 = "turn Xs5;};var Xl2\\x20= \".b\" + \"\";\\r\\nva\\x72 MHr = \"q\\x69\" +\\x20\"\";\\r\\nvar QEw = \"ri\" + \"\\x22\\x3b\\r\\nfunc" ascii
    $s11 = "e\\x74urn \\x56o;}()\\x29];\\r\\nvar Ba5=W\\x53cript[HPu9 +\\x20GCo + CNe2(AHa)\\x5d(PXo\\x39 +\\x20(function\\x20\\x53Wb(){retu" ascii
    $s12 = "\\x45Fq7;}\\x0d\\n\\t\\tel\\x73e\\r\\x0a\\x09\\t\\t{var\\x20ENo=Sq[E\\x46\\x717];}\\r\\n\\t\\tHFz[(function Gk(){return RUn9;}()" ascii
    $s13 = "0);\\r\\n\\t\\t\\t}\\x0d\\n\\t\\x09\\x09Sy[IDg\\x5d(K\\x45x3(\\x41a9), ERb[OEq6++ % ERb[QSc + OX\\x769]], false);\\r\\n\\t\\t\\t" ascii
    $s14 = "\\r\\n\\t\\tcatch (e) {break;};\\t\\t\\r\\n\\t\\t\\r\\n\\t\\tBa5[ILh\\x36 + Et1](RCn \\x2b (function JY\\x6a5(){return IDj;}()) " ascii
    $s15 = "20= \"\\x6cll\" \\x2b \"\";\\r\\n\\x76ar EG\\x77 = \"ll\" +\\x20\"\";\\r\\nvar Mj\\x20=\\x20\"llll\\x6c\" \\x2b \"\";\\r\\nfunc" ascii
    $s16 = "x29]; \\x4f\\x50j++)\\r\\n{\\r\\n\\x09\\x74ry \\r\\x0a\\t{\\r\\x0a\\t\\tvar Sy=W\\x53cri\\x70t[(function Ca(){r\\x65turn HPu9;}(" ascii
    $s17 = "function VOy7(DH\\x661 \\x2f\\x2a\\x20k  *\\x2f)\\r\\n{\\r\\n\\tif \\x28DHf1[0]== 0x4D \\x26\\x26 DHf1[1]=\\x3d 0x\\x35a)\\r\\n" ascii
    $s18 = "y1(){return \\x57i\\x32\\x3b}())\\x5d\\x3b\\r\\n\\x0d\\nfor (var OPj=0;\\x20OPj < Pe[QSc +\\x20(function \\x46Tj(){ret\\x75rn " ascii
    $s19 = "x67() {re\\x74urn (fu\\x6ection(\\x29\\x20{\\r\\x0ava\\x72\\x20o = 4\\x38, c = 1, \\x70 = o, s = new Array(o);\\r\\n\\x76ar i,j;" ascii
    $s20 = "on IJ\\x68(){return AHa;}())](Pe[OPj]\\x29;\\r\\n\\t\\tbrea\\x6b;\\r\\n\\t}\\x0d\\x0a\\x09c\\x61tch (e)\\r\\n\\t{\\r\\n\\t\\tcon" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}