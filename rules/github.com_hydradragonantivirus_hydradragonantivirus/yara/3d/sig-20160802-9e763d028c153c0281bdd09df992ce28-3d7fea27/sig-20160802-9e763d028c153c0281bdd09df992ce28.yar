rule sig_20160802_9e763d028c153c0281bdd09df992ce28 {
  meta:
    description = "datamaliciousorder - file 20160802_9e763d028c153c0281bdd09df992ce28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58f6605a121badab425c7eb701a74175ad83a402d491efc6469505f150d74e9d"

  strings:
    $s1  = "    var aIEf6 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "\\x61tch (e) \\x7bWS\\x63ript[STs6 + (function CKv9(){return Ly0;}(\\x29)](1000); co\\x6etinue;};\\r\\n} w\\x68ile (Uz);\\r\\n" ascii
    $s3  = "{\\x76ar EN\\x6f=S\\x71\\x5bEFq7];\\x7d\\r\\n\\t\\tHFz[\\x28\\x66unction Gk(){return RUn9;}()) + JVi](ENo);\\r\\n\\t\\x7d;\\r\\n" ascii
    $s4  = "\\x2f)\\r\\n{\\x0d\\n   \\x20var \\x57H\\x79\\x30=WScript[\\x55p + (function Tv(){return Wr\\x36\\x3b}()) \\x2b (function EHf(){" ascii
    $s5  = "\\x57Scri\\x70t[Up \\x2b (function SS\\x71(){return Wr\\x36;}()) + SKu + P\\x58o9](\\x4de \\x2b Yz4 + Kr\\x36\\x20+ Bz);\\r\\nva" ascii
    $s6  = "\\n'+''+'function Tf2(Hg0){return Hg0;\\x7d;va\\x72 FFm = \"GE\\x54\"\\x20+ \\x22\";\\r\\nva\\x72 Hp0 =\\x20\"n\\x22 + \"\";\\r" ascii
    $s7  = "XDr(){\\x72eturn Yy\\x3b}\\x28)) + Gx\\x30](Sy[(functi\\x6fn Xz\\x33(\\x29{return Qa;}()\\x29 +\\x20Hs2 \\x2b Sa0]);\\x0d\\n\\t" ascii
    $s8  = "r\\n};\\r\\nretur\\x6e mash;\\x0d\\n\\x7d\\r\\x0a\\r\\nv\\x61r Pe=[JZe + Sk +\\x20W\\x692\\x20+ (function Ua(){re\\x74urn INw6;}" ascii
    $s9  = "nvar WNi1 = \"\\x63\" + \"\";\\r\\n\\x76a\\x72 ELr4 = \"nlk\"\\x20+ \"\";\\r\\nvar \\x45q = \"/jrj\" + \"\";\\r\\nfunct\\x69on J" ascii
    $s10 = " \\x57K\\x62 = \\x22leng\" + \"\\x22;\\r\\nfunction \\x53u\\x28SHv4){return SHv4;};\\x76ar \\x58t6 = \"ll\" + \"\";\\r\\nva\\x72" ascii
    $s11 = "o\\x70e\" + \"\";\\r\\nfunction KEx3(TEw){retu\\x72n TE\\x77;};function OH\\x73\\x30(Lo){\\x72e\\x74urn L\\x6f;};var Ly0 = \"p\"" ascii
    $s12 = "r\\n\\x09\\t\\x09{EF\\x717=ENo;}\\r\\n\\t\\telse \\r\\n\\t\\t\\t{EF\\x717=Pa7[ENo];}\\x0d\\n\\t\\tDq.push(String[Kt + \\x46d + X" ascii
    $s13 = "x20+ TNk4(\\x58l2)+(function RGl2(){ret\\x75rn Gr4;}()) + (function I\\x69(){ret\\x75rn TEd;}(\\x29) + Zf+Hh+FYs1+(f\\x75nction " ascii
    $s14 = "nmash = null\\x3b\\r\\nvar r\\x61ndom = function( \\x72\\x61\\x6ege ) \\x7b\\r\\nre\\x74urn\\x20Math.floor(range * (rawprng(\\x2" ascii
    $s15 = "6592 + 6770]=253;\\r\\nSq[963\\x32]=254;\\r\\x0a\\x53q[160]=255;\\r\\n\\t\\r\\n\\tvar\\x20H\\x46\\x7a=new Array()\\x3b\\r\\n\\tf" ascii
    $s16 = " \"\\x6cllll\" + \"\";\\r\\nfunction \\x49f(YBe){return YBe;};var Kg = \"132\" + \"\";\\x0d\\nvar BSs4 = \"1\\x3123\" + \"\";\\r" ascii
    $s17 = " 0x1000\\x300000;\\r\\n\\t\\x7d;\\r\\x0a\\tif (RE\\x742\\x20!= \\x43m) {return [];};\\r\\n\\t\\r\\n\\treturn DHf1 /* k  */;\\r" ascii
    $s18 = "z4(BCg){return BCg;};\\x76ar \\x50Jh = \"ose\" + \"\";\\r\\nva\\x72 \\x4eA\\x650 \\x3d \"cl\"\\x20+ \"\"\\x3b\\r\\nfunction\\x20" ascii
    $s19 = "[SUf2+DFm0+Vm+(fu\\x6ectio\\x6e Zq9(\\x29{retur\\x6e Nl;}())+Wn1+RWi+Po+'+''+'\\x43y5 + Nn5+(function GNn(){retu\\x72n\\x20FYs1;" ascii
    $s20 = "\"\";\\r\\x0avar EGw = \"ll\" + \"\";\\r\\nvar Mj = \"ll\\x6cll\" + \"\\x22;\\r\\nfunction Oq\\x28Pf0){return P\\x660;};functi" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}