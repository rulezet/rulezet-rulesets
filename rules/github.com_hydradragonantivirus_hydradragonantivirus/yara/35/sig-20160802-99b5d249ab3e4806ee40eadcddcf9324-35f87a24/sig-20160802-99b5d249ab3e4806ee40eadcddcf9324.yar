rule sig_20160802_99b5d249ab3e4806ee40eadcddcf9324 {
  meta:
    description = "datamaliciousorder - file 20160802_99b5d249ab3e4806ee40eadcddcf9324.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6afce567320e57479c59f61122dce2332234580f9e72229c2034075baaa647c9"

  strings:
    $s1  = "    var aVLd = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "t\\x63atch (e\\x29 {WScript[Sp](1000)\\x3b continue;\\x7d\\x3b\\r\\n} while (Uz\\x29;\\r\\n\\r\\x0aWScri\\x70t.Quit(0);\\r\\x0a" ascii
    $s3  = "\\x65turn As3;}()\\x29 + (f'+''+'unction EL\\x724(){return Z\\x75;}())](XHf5+\\x28functio\\x6e Od\\x28){re\\x74urn \\x4ds;}())+B" ascii
    $s4  = "9 = \"leng\" + \"\";\\r\\nvar Dp \\x3d \"sh\" + \"\";\\r\\nvar U\\x66\\x20\\x3d \\x22pu\" + \"\";\\r\\n\\x66unctio\\x6e WXb(\\x4" ascii
    $s5  = "x0d\\n\\x66un\\x63tion \\x57Wf\\x33(IUg){\\x72etu\\x72n IUg\\x3b};function JHt6\\x28DIl4){r\\x65turn \\x44Il4;};va\\x72 QGh = \"" ascii
    $s6  = "r\\x65turn Qk5;};function Gm2(G\\x68){return \\x47h;};var Q\\x53n9 =\\x20\"t\\x22 + \"\";\\r\\nvar QQj2 = \"se\" + \"\"\\x3b\\r" ascii
    $s7  = "x3d\\x20Cm\\x29 {return [];};\\r\\x0a\\t\\r\\x0a\\treturn D\\x48f1 /*\\x20\\x71  */;\\r\\n};\\r\\n\\r\\n\\r\\nfunct\\x69\\x6fn V" ascii
    $s8  = "63 + (function FTj(){return OXv9;}())]; OPj++)\\r\\n{\\r\\n\\x09try \\r\\n\\t{\\r\\n\\t\\t\\x76ar Sy=WScri\\x70t[(fu\\x6e\\x63ti" ascii
    $s9  = "BSs4 =\\x20\"1123\" + \"\";\\r\\nvar Mz9=(BSs4 + If(Kg), Jl\\x39 + CZy + IIk2 \\x2b (function NKy0(){return EYf;}\\x28)));\\r\\x" ascii
    $s10 = "d1 = \"pe\\x22 \\x2b \"\"\\x3b\\r\\nvar \\x47Mf\\x20=\\x20\"ty\" + \"\";\\r\\nvar BRc = \"\\x6fpen\" + \"\";\\r\\nfunction Ee\\x" ascii
    $s11 = " * 2.3283064365386963e\\x2d10;\\x0d\\n} else n = 0xefc8249d;\\x0d\\n}\\x3b\\r\\nreturn mash;\\r\\n}\\r\\n\\r\\nvar \\x50e\\x3d[J" ascii
    $s12 = "Xv9];\\x0d\\n\\x76ar Pe0=(D\\x763 + KJd + (func\\x74ion IMn\\x28){return CZ\\x698;}()\\x29\\x2c Zs5 + Te1 + Su(MSl) + X\\x746\\x" ascii
    $s13 = "l(EHf) \\x2b PQk1;\\r\\nvar RCn=RJp2 + \\x57Cr0 \\x2b (functio\\x6e PMw7(){return KFx3;}());\\r\\n\\r\\nfunction uheprng() \\x7b" ascii
    $s14 = "i3){return AJi3;};var ZWp = \"12\" \\x2b \"\";\\r\\nvar GQc4 = \"/2\" + \"\"\\x3b\\r\\n\\x76ar Fb = \":/\" + \"\"\\x3b\\r\\nfunc" ascii
    $s15 = "r Oj2\\x20= \"\\x65rd.i\" + \"\";\\r\\nfunct\\x69on \\x4d\\x48r(Xl2){return Xl\\x32;};var Ew = \"n\" + \\x22\";\\r\\n\\x76ar Kv " ascii
    $s16 = "x7d;fun\\x63tion FDz2(Mx\\x29{ret\\x75r\\x6e M\\x78;};f\\x75nction\\x20Ih2(GT\\x67\\x29{return GTg;};var\\x20\\x4ci4\\x20= \"le" ascii
    $s17 = "return Ei;}\\x3bvar \\x53Uf2 \\x3d \"h\\x74tp\" + \"\";\\r\\nvar Lc =\\x20\"7\" + \"\";\\r\\x0avar Ep\\x33 \\x3d\\x20\"43\" +\\x" ascii
    $s18 = "UWy4\\x3d\\x50e0[QSc + (function LBy(){return OXv\\x39\\x3b}(\\x29)];\\r\\n\\r\\nvar GRx5=1;\\r\\nvar\\x20DAe=2;\\r\\nvar Ya=360" ascii
    $s19 = "x59h;}(\\x29) + Ek + (f\\x75nction Q\\x4dy\\x28\\x29{return Hn;}()) + GIm](EFq\\x37));\\r\\n\\x09}\\r\\n\\t\\r\\n\\tOg=Dq[Vq9 + " ascii
    $s20 = "P\\x617[255]=160;\\r\\n\\t\\r\\n\\tvar Dq=new Array(\\x29;\\r\\n\\tvar\\x20Og=\\x22\";\\r\\n\\tvar EN\\x6f\\x3b\\x20var EFq7;\\r" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}