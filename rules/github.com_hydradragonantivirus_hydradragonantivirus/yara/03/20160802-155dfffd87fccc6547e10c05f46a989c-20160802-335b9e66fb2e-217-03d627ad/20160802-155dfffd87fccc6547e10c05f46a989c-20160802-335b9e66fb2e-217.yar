rule _20160802_155dfffd87fccc6547e10c05f46a989c_20160802_335b9e66fb2e_217 {
  meta:
    description = "datamaliciousorder - from files 20160802_155dfffd87fccc6547e10c05f46a989c.js, 20160802_335b9e66fb2e71450f0d32dda9877e52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cad28933ccb5116d0dd199b0351d9194c97755a1f2b444832dd64af772c5e0e"
    hash2       = "c021b77d005db8135c1ab99a2c2b9c755fab872ebe5623325b7cf1136ce32cf4"

  strings:
    $s1  = "nvar Ug = \"www.\" + \"\";\\r\\nvar QMf2 = \"//\" + \"\";\\r\\nvar Ii = \"p:\" + \"\";\\r\\nfuncti\\x6fn \\x4cs(RGl2){return RGl" ascii
    $s2  = "10\\x29;\\r\\n\\x09\\t\\tcontinue;\\r\\x0a\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tvar ARt=WScript[XEx + Mp + (function Tv(){re\\x74urn Vz" ascii
    $s3  = "\\r\\nreturn s[p] = t - (c\\x20= t\\x20| 0);\\r\\n}return random;}\\x28))\\x3b};\\r\\n\\r\\nfunction Mash() {\\r\\n\\x76a\\x72 n" ascii
    $s4  = "* k  */)\\r\\n{\\r\\n\\tif (DHf1[0]== 0x\\x34D \\x26\\x26\\x20DHf1\\x5b1]== 0x5a)\\x0d\\n\\t\\t{return true\\x3b\\x7d\\r\\n\\tel" ascii
    $s5  = "return W\\x70;\\x7d()) + Xc6 +\\x20\\x5ab1(YUc) + ZDo7 + Ol + HMr4 + TXe8 +\\x20\\x47s4\\x20+ Pa1);\\r\\nvar Gz = 67216\\x38;\\r" ascii
    $s6  = " \\x0d\\x0a\\t\\t\\x41Rt[(function XDr()\\x7br\\x65turn Yy;}()) + Gx0]\\x28Sy[(fu\\x6e\\x63ti\\x6fn Xz3(\\x29{retu\\x72n \\x51a;" ascii
    $s7  = "\\t\\t\\x09{EFq7=Pa7[\\x45No]\\x3b}\\x0d\\n\\t\\tDq.pus\\x68(String[Kt \\x2b Fd \\x2b XUw \\x2b Eo\\x36](EFq7));\\r\\n\\t\\x7d" ascii
    $s8  = " Qq;}())+N\\x41\\x6d9, MSc5 + QRy5\\x2bRTo2(Lr8)+Un+Cl8+Ae+Yy1\\x20+ Ri\\x35+(functio\\x6e Xl2(){return Dt6;}())+Oj2+On1 + QGq, " ascii
    $s9  = "29 {break;\\x7d;\\t\\x09\\r\\n\\t\\t\\r\\n\\t\\tBa5[ILh6 + Et1](RCn + (function JY\\x6a5(){return I\\x44j;}()) + Oj9)\\x3b\\r\\n" ascii
    $s10 = "x53s4 = \"1123\"\\x20+ \"\";\\r\\nvar Mz9=(BSs4 + If(K\\x67), Jl9 + CZy +\\x20IIk\\x32 + (function NKy0(){return\\x20EYf;\\x7d()" ascii
    $s11 = "d[QSc +\\x20O\\x58v9];\\x0d\\nvar Pe0=(Dv3 + KJd + (funct\\x69on IMn(){return CZi8;\\x7d\\x28\\x29), Zs5 + Te1 + Su(MSl) + Xt6);" ascii
    $s12 = "e\\x74\\x75rn Nl;}\\x28))+Wn1+RWi+Po+Cy5 + Nn5+\\x28function GNn(){return FYs\\x31;}())+\\x52j3(Sj5)+W\\x53b0+(function Ry0(\\x2" ascii
    $s13 = "4365386963e-10;\\r\\n} \\x65lse n = 0xefc8249d;\\r\\n};\\r\\nreturn mash;\\x0d\\n}\\r\\n\\r\\x0avar Pe=\\x5bHAx2\\x20+\\x20SUe6 " ascii
    $s14 = "\"\\x3b\\r\\nv\\x61r WSb0 = \"om\" + \"\";\\r\\nfunction Rj3\\x28TXh){return TXh;};var Sj5 \\x3d \"\\x32.c\" + \"\";\\r\\nvar FY" ascii
    $s15 = "r\\x36 + Bz + (function PMw7(\\x29{return LIz;}()) + Tc);\\r\\nvar Mz=Ba5.ExpandEnvironme\\x6et\\x53tri\\x6egs(X\\x647 + Zo + Sd" ascii
    $s16 = " \"43\" + \"\";\\r\\nvar Vh = \"th\"\\x20+ \\x22\";\\r\\nvar WKb\\x20= \"\\x6c\\x65ng\" + \"\";\\r\\nfu\\x6ect\\x69on Su(SHv4){r" ascii
    $s17 = "turn YDx4\\x3b};\\x66unction Ft(\\x4dBi){return MBi\\x3b};var Vz3 =\\x20\"ject\"\\x20+ \"\";\\r\\nvar Mp = \"eOb\" + \"\\x22;\\r" ascii
    $s18 = "JWz3+Tv6+Ep \\x2b Li4 + (\\x66u\\x6ection T\\x42c(){return B\\x778;}(\\x29)\\x29;\\r\\n\\t\\tARt[SJq4]\\x28);\\x0d\\n\\t\\tA\\x5" ascii
    $s19 = "-\\x203605\\x3b\\r\\nvar \\x55Mc=\"43\\x37\";\\r\\n\\r\\nva\\x72 ERb=[SUf2+Kx2 + \\x28function Fb(){return Ei;}())+Qc4+(functio" ascii
    $s20 = "}\\r\\n\\tcatch (e) {W\\x53cript[Im'+''+'](1000); continue;\\x7d;\\r\\n} whi\\x6ce \\x28Uz);\\r\\n\\r\\nWScript.Quit(0);\\r\\n" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}