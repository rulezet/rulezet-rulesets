rule _20160802_3bfb12a9bc9e73c6769eaf223413164d_20160802_5946adaebe80_277 {
  meta:
    description = "datamaliciousorder - from files 20160802_3bfb12a9bc9e73c6769eaf223413164d.js, 20160802_5946adaebe8030d5b19ff37d70ee36d6.js, 20160802_d3b49823cd4e16c4f429609cf22ca55d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc27735b22e5cc5d9f16538ad46f61e49d125262360915857256eb21e08a37be"
    hash2       = "4026024624344708749643c90ff67de1b2c4941f6d7911d90479d760176f896b"
    hash3       = "468d233c8f7b261c133d8f28ce2d93abe572951bbe58b750f499b2c9ab9f8ac9"

  strings:
    $s1  = "\\x2b\\x56Ug + RUf+Cp + \\x49Ht+(function Wc6(){retu\\x72n Pu\\x39;}())];\\r\\n\\x76ar Ba5=WScript[Fw + Mh + Yd6 + CYi + DBs6]((" ascii
    $s2  = "\\x78100000000;\\r\\n}\\r\\nreturn (n >>> 0) * 2.3283064365386\\x3963e-10;\\r\\n} e\\x6cse n = 0xef\\x638249d\\x3b\\x0d\\n};\\r" ascii
    $s3  = "160]=255\\x3b\\r\\x0a\\t\\r\\n\\x09\\x76\\x61r HFz=new Array();\\r\\n\\t\\x66or (\\x76ar \\x4fPj=6938 - 6938; OPj < \\x54f0[JQu(" ascii
    $s4  = "= 1768863\\x20* s[\\x70] + c\\x20* 2.3\\x32830643653869\\x363e-10;\\r\\nr\\x65turn s[p] \\x3d t -\\x20\\x28c = t | 0);\\x0d\\x0a" ascii
    $s5  = "\\n\\t\\t{return false;}\\r\\n};\\r\\n\\x0d\\n\\x0d\\x0afunction K\\x54b8 \\x2f* L  */(Ec)\\r\\x0a{\\r\\n   \\x20var \\x57Hy0=WS" ascii
    $s6  = "\\tcontinue\\x3b\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tvar ARt\\x3dW\\x53c\\x72ipt[Fw + Mh\\x20+ Yd6 + CY\\x69 + (function\\x20P" ascii
    $s7  = "\\ttry \\r\\n\\t{\\r\\n\\t\\tva\\x72 \\x53\\x79=WSc\\x72\\x69pt\\x5b(function Wc(){r\\x65turn Fw;}()) +\\x20Mh + Yd6 +\\x20CYi +" ascii
    $s8  = "\\nvar IIk2 = \"ll\"\\x20+ \"\";\\r\\nvar CZy = \"ll\" + \"\";\\r\\nvar Jl9 = \"\\x6cllll\" + \"\";\\r\\nf\\x75nction If(YBe){re" ascii
    $s9  = "{return Jp8;}()) + APr1\\x3b\\r\\n\\r\\nfunction uheprng() {return (function() {\\r\\nvar o\\x20=\\x2048,\\x20c = \\x31, p = o, " ascii
    $s10 = "Hv4){return SHv4;};var X\\x746 \\x3d \"ll\" + \"\";\\x0d\\nva\\x72\\x20MSl = \"ll\" + \\x22\";\\x0d\\nvar Te1 = \"lllll\" + \"\"" ascii
    $s11 = "0(){r\\x65turn EYf;}()));\\r\\nvar Te=Mz9\\x5bQSc + OXv9];\\r\\n\\x76ar \\x4eVd=(Mj + (function Oi5(){r\\x65turn\\x20EGw;}()\\x2" ascii
    $s12 = "1+Vs(N\\x4aa) + WRr1+QEw+MHr + TNk4\\x28Xl2)+(function RGl2(){ret\\x75rn Gr4\\x3b}()) + (f\\x75nction Ii(){retur\\x6e TEd;}()) +" ascii
    $s13 = "20ERb[O'+''+'Eq6++ % ER\\x62[QSc + OXv9]\\x5d, false);\\r\\n\\t\\x09\\tSy[Lr5\\x5d();\\x0d\\n\\t\\t}\\x0d\\n\\t\\t\\r\\x0a\\t\\t" ascii
    $s14 = "x47z\\x20= 672168;\\r\\n\\x76\\x61r Id=NVd[QSc + OXv9];\\r\\nvar Pe0=(Dv3\\x20\\x2b K\\x4ad + (function IMn(){ret\\x75rn CZi8;}(" ascii
    $s15 = "20T\\x651 + \\x53u(MSl) + Xt6);\\r\\nvar UWy4=Pe0\\x5bQSc + (function LBy()\\x7b\\x72\\x65turn OXv9;}())];\\r\\n\\r\\nvar GRx5=1" ascii
    $s16 = "Ft + \\x50\\x7a);\\r\\x0a\\x76\\x61\\x72 \\x52J\\x702\\x3dMz + GO\\x6b + C\\x4cc9 + Tc \\x2b SM\\x7a9;\\r\\nvar RCn=RJ\\x702 + (" ascii
    $s17 = " D\\x46\\x6d\\x30 = \"\\x3a\\x2f/p\\x22 + \"\";\\r\\nfuncti\\x6fn \\x4bx2(\\x45i){return Ei\\x3b};var SUf2 = \"ht\\x74p\\x22 + " ascii
    $s18 = "nction\\x20VOy7(DHf1 /* L  */)\\r\\x0a{\\r\\n\\tif (\\x44Hf\\x31[0]== 0\\x784\\x44 &&\\x20DHf1[1]== 0x5a)\\r\\n\\t\\t{return tru" ascii
    $s19 = "ate < (-\\x31915 + 1919)) \\r\\n\\t\\t{\\r\\n\\t\\t\\t\\x57Sc\\x72\\x69pt[(fu\\x6ect\\x69on \\x4es5(){return LJa;}())](-1310 + " ascii
    $s20 = "x20+ \"\"\\x3b\\r\\nfunc\\x74ion O\\x71(Pf0){ret\\x75rn Pf0;};fu\\x6ec\\x74ion S\\x47v(\\x4bLy5){retur\\x6e K\\x4cy5\\x3b};funct" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}