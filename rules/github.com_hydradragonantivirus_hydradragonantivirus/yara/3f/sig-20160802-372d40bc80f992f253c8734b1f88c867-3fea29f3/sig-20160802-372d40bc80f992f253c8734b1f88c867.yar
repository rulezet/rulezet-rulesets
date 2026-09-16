rule sig_20160802_372d40bc80f992f253c8734b1f88c867 {
  meta:
    description = "datamaliciousorder - file 20160802_372d40bc80f992f253c8734b1f88c867.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c77808066a87c9b52a42a3eb9ba0c57e8674b59af2ffe89e3429a98eaa15a2e3"

  strings:
    $s1  = "    var aPBe3 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "r\\nn = h >>> 0;\\r\\nh -= n;\\r\\nn += h * 0x100000\\x3000;\\r\\n}\\r\\nretu\\x72n (n >>> 0)\\x20* 2.3\\x32\\x383064365386963e-" ascii
    $s3  = "\\r\\nvar WSb0 = \"p:\" + \"\";\\r\\nfu\\x6ection Rj3(TXh){return TXh;\\x7d;v\\x61r Sj5 = \"htt\" + \"\\x22;\\r\\nvar F\\x59\\x7" ascii
    $s4  = "nue\\x3b};\\x0d\\n} while (Uz);\\r\\n\\r\\nWScript.Quit(0);\\r\\n\\r\\nfunc\\x74ion BKw(DHf1\\x20/* k  */)\\r\\n{\\r\\x0a\\tvar " ascii
    $s5  = "53;\\x0d\\x0a\\x53q[9632]=254;\\r\\nSq[160]\\x3d255;\\x0d\\n\\t\\r\\x0a\\tvar HFz=new Array();\\r\\x0a\\tfor (var OPj=\\x36938 -" ascii
    $s6  = "] = \\x74 - \\x28c = t | 0);\\x0d\\n}re\\x74urn random;}());};\\r\\n\\r\\n\\x66unction Mash() {\\r\\nvar \\x6e = 0xefc8249d;\\r" ascii
    $s7  = "''+'OEq6++ % E\\x52b[QSc + OXv9\\x5d], false);\\r\\n\\x09\\t\\tSy[KE\\x783(A\\x619)](\\x29;\\r\\n\\t\\x09}\\r\\n\\t\\t\\r\\n\\t" ascii
    $s8  = "fu\\x6ecti\\x6fn JYj5\\x28){return \\x49Dj;}()) \\x2b Oj9);\\r\\n\\t\\tbreak;\\r\\n\\t}\\r\\n\\tc\\x61tch (e) {WScript[Yv3(QSi)]" ascii
    $s9  = "\\r\\n\\t{\\r\\n\\t\\tREt2=(\\x52Et2 + DHf\\x31[OPj]) % 0x10000\\x30000;\\r\\x0a\\t};\\r\\n\\tif (REt\\x32 != Cm) {return [];};" ascii
    $s10 = "20= \"1123\" + \"\";\\r\\nvar Mz9=(BS\\x734 + If(Kg), Jl\\x39 + \\x43Zy + IIk2 + (function NKy0\\x28){re\\x74urn EYf\\x3b}()));" ascii
    $s11 = "4=\\x50e0[QS\\x63 + (fu\\x6ection LBy(){return O'+''+'\\x58v9;}())];\\r\\n\\r\\nvar GRx5=1;\\r\\nvar\\x20D\\x41e=2;\\r\\n\\x76ar" ascii
    $s12 = "n\\x20= 0xef\\x638\\x324\\x39d;\\r\\x0a};\\r\\nreturn mash;\\x0d\\n\\x7d\\r\\x0a\\r\\nvar Pe=[Sr6 + Va3\\x28Oj5) + Ik \\x2b RJz " ascii
    $s13 = "- 36\\x305;\\r\\nva\\x72 UMc=\"43\\x37\";\\r\\n\\r\\nvar ERb=[SU\\x662+Kx2 + (function Fb(){return Ei;}())+Qc4\\x2b(f\\x75nction" ascii
    $s14 = "55]=16\\x30;\\x0d\\x0a\\t\\r\\n\\tvar Dq=new Array();\\r\\n\\t\\x76ar Og\\x3d\"\";\\r\\n\\tvar ENo; var EFq7;\\r\\x0a\\x09fo\\x7" ascii
    $s15 = "3c Tf0[JQu(QSc) + (function Cn2(){r\\x65turn OX\\x76\\x39;}())]; OPj++)\\r\\n\\t{\\r\\n\\x09\\t\\x76\\x61r EFq7=Tf0[X\\x754 + ID" ascii
    $s16 = "e\\x74urn Nl;}())+Wn1+RWi+Po+C\\x795 + Nn5+(function GNn(){r\\x65turn F\\x59s1;}()), \\x52j3(Sj5)+WSb0+(fun\\x63tion Ry0(){retur" ascii
    $s17 = "\"\";\\r\\nvar \\x56h \\x3d \"th\" + \"\";\\x0d\\nva\\x72\\x20WKb = \"leng\" \\x2b \"\\x22;\\r\\nfunction Su(SHv4){return SHv4;}" ascii
    $s18 = "i]\\x20= mash(\\x47z);\\r\\nmash = null;\\x0d\\x0a\\x76ar ra\\x6edom \\x3d fu\\x6ection( range ) {\\r\\nreturn Mat\\x68.fl\\x6fo" ascii
    $s19 = "en\" + \\x22\";\\r\\nvar KKb3 = \"GE\\x54\" + \\x22\";\\r\\nfu\\x6ection Io3(\\x47b){return Gb;};var\\x20Sp = \"n\" + \"\";\\r" ascii
    $s20 = "b \"\";\\r\\n\\x76ar \\x59i = \"WSc\" + \"\";\\r\\nf\\x75nct\\x69\\x6fn Je4(LFp){retur\\x6e LFp;};function KQ\\x649(ZO\\x639){re" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}