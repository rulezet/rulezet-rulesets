rule sig_20160802_600a41797f90e8f9fdb0ceb32f0223a6 {
  meta:
    description = "datamaliciousorder - file 20160802_600a41797f90e8f9fdb0ceb32f0223a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e76665fd43a19d1346b803a947b01375b08b051229052d4b921798bdc3e113b"

  strings:
    $s1  = "    var aJCi4 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "20+ (funct\\x69on\\x20CKv9(){return Ly0;}())](1000); continue;};\\x0d\\n} while (Uz\\x29;\\r\\n\\r\\nWScript.\\x51uit(0);\\r\\n" ascii
    $s3  = "Pj < Pe[QSc + (fun\\x63tion FTj(){return OXv9;}())]; OPj++)\\r\\x0a{\\r\\n\\tt\\x72y \\r\\n\\t{\\r\\x0a\\t\\tva\\x72 \\x53y=WScr" ascii
    $s4  = "\\n\\tv\\x61r HFz=new Array();\\r\\n\\tfor (var OPj\\x3d6938 - \\x36\\x3938; OPj < Tf0[JQu(QS\\x63)\\x20\\x2b (function C\\x6e2(" ascii
    $s5  = "nf'+''+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nv" ascii
    $s6  = "3653869\\x363e-1\\x30;\\r\\nre\\x74urn s\\x5bp] = t - (c \\x3d t | 0);\\r\\x0a}return ra\\x6edom;\\x7d\\x28));};\\r\\n\\r\\nfu" ascii
    $s7  = "\\n\\t\\t}\\r\\x0a\\t\\t\\r\\n\\t\\tvar ARt=WScrip\\x74[\\x4am\\x20+ Fe + JHu8\\x20+ Ot8](Oa4\\x28Ea)+JWz3+Tv6\\x2bE\\x70 + Li4 " ascii
    $s8  = "avar Wn = \"e\\x6e\" + \"\";\\r\\nvar El9\\x20= \"op\" \\x2b \"\"\\x3b\\r\\n\\x66unctio\\x6e \\x45q9(Mn){return Mn;};var \\x55q " ascii
    $s9  = "29{retu\\x72n \\x56k;};fu'+''+'\\x6ection \\x4e\\x47e4(NSs5){return NSs5;};var XHa =\\x20\\x22ext\" + \"\";\\r\\nvar IGy0 = \"R" ascii
    $s10 = "turn MGd;};var Ir8 = \"eAt\" + \"\";\\r\\nva\\x72 RVk = \"od\" + \"\";\\r\\x0a\\x76\\x61r\\x20Xu4 = \"char\\x43\" + \"\"\\x3b\\r" ascii
    $s11 = ", Kx2\\x28SUf2)+(function WJf(){re\\x74urn NJa;}())+SKi9 + IKv+A\\x71 + HJj\\x39+Oj2 + Wb\\x34+Lq3, SUf2+Zf + R\\x6c3(BIq5)+VUk3" ascii
    $s12 = "Zq){return CZq\\x3b};v\\x61r Pa1 = \"l\" + \"\"\\x3b\\r\\nvar Gs4 = \"llll\\x6c\" + \"\"\\x3b\\r\\nv\\x61r\\x20TXe8 =\\x20\"ll\"" ascii
    $s13 = "0(ZW\\x70)+CRy4\\x2bSOm3+O\\x43z5+UAm8+\\x4eUm5 + QTb2 + Rj3+\\x4dWq0 + (function UDw9(){return Th;}())+Ev8\\x28AN\\x78) + Rw\\x" ascii
    $s14 = "Xz4(BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52" ascii
    $s15 = "2\";\\r\\x0avar SFh = \"i\"\\x20+ \"\";\\r\\nfuncti\\x6fn Ev8(XCn9){return XCn9;\\x7d;var \\x52w\\x20= \"b\" \\x2b \"\";\\r\\nva" ascii
    $s16 = "e> \\x30) * 2.3283064365386963e-10;\\r\\n} else n = 0xefc8249\\x64;\\r\\n};\\r\\nretur\\x6e mash;\\r\\n}\\r\\n\\x0d\\nvar \\x50" ascii
    $s17 = "n false;}\\r\\n};\\r\\n\\r\\n\\r\\nfunction KT\\x628 \\x2f\\x2a\\x20k  *\\x2f(Ec)\\r\\n{\\r\\n \\x20  var WHy0=WScr\\x69\\x70t[J" ascii
    $s18 = "4[M\\x734 + (function Er8(\\x29{\\x72eturn VJk5;}()) + J\\x47m3](RJ\\x70\\x32, \\x59a);\\r\\n\\t\\x09ARt[N\\x41e0\\x20+ PJh]();" ascii
    $s19 = "34\\x20\\x3d \"/l\\x22\\x20+ \\x22\";\\r\\nvar Fb = \"\\x3a/\"\\x20+ \"\\x22;\\r\\nfunction \\x4bx2(Ei){return Ei\\x3b}\\x3bvar " ascii
    $s20 = "return Math\\x2efloor(r\\x61nge * (rawprng() \\x2b\\x20\\x28rawpr\\x6eg() \\x2a 0x\\x3200000 | 0) * 1.1102230246251\\x3565e\\x2d" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}