rule sig_20160802_0f233ab0bd29f65e4c1fd190ad5b969c {
  meta:
    description = "datamaliciousorder - file 20160802_0f233ab0bd29f65e4c1fd190ad5b969c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbd9de247fae19742373dcaef966c4f929153ddb0abcb4546b8ab4576d692de0"

  strings:
    $s1  = "    var aHNo7 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = " OPj=0; OPj\\x20<\\x20Pe[QSc + (function FT\\x6a(){\\x72eturn OXv9;}\\x28))]; OPj++)\\r\\n{\\r\\n\\ttry \\r\\n\\t{\\r\\n\\t\\tva" ascii
    $s3  = "tfor \\x28var OPj=6938 - 6938\\x3b OPj < Tf0[JQu'+''+'(QSc)\\x20+ (function Cn2(){return OXv9\\x3b}())\\x5d; \\x4fPj++)\\r\\x0a" ascii
    $s4  = "\\x63tion SGv(KLy5){retur\\x6e KLy5;}\\x3bf\\x75nction JQ\\x75(KKh4){return K\\x4bh4;};va\\x72 OXv9 = \"gt\\x68\" + \"\\x22\\x3b" ascii
    $s5  = "\\x20+ ESh(Ns5) + UOw0 + PTe + OHs0\\x20+ Lo, RFc4 + (func\\x74ion YVv(){return Yj;\\x7d(\\x29)\\x20+ Kf1 + Ee]\\x3b\\r\\n\\r\\n" ascii
    $s6  = "\\nvar random = function( range ) {\\r\\nreturn \\x4dath.floor(ra\\x6ege * (rawpr\\x6eg() +\\x20\\x28rawprng() * 0x200000 | 0) *" ascii
    $s7  = "x22\";\\r\\nvar Fl2 = \"kan\" + '+''+'\"\";\\x0d\\n\\x66unction \\x59d6(CYi){return CYi;\\x7d;var Sg7\\x20= \"a\" +\\x20\"\";\\r" ascii
    $s8  = "88\\x363 * s[p] + c * 2.3283064365386963e-10\\x3b\\r\\nret\\x75rn s[p]\\x20= t \\x2d \\x28c = t | 0);\\r\\n}re\\x74u\\x72n rando" ascii
    $s9  = "g\\x22 + \\x22\";\\r\\nfunction AFs(TGr4){return TGr\\x34;};var Bl = \"pb\" + \"\";\\r\\nva\\x72 Q\\x75 = \"ru/\" + \"\";\\r\\nv" ascii
    $s10 = "t\\tREt2=(REt2 + DHf1[OPj]) % 0x10000\\x30000;\\r\\n\\t\\x7d;\\r\\n\\x09i\\x66 \\x28REt2 != Cm)\\x20{return [\\x5d;};\\r\\n\\t" ascii
    $s11 = "3+Qu + AFs(Bl\\x29+(func\\x74ion AXa\\x28){retu\\x72\\x6e V\\x63;}\\x28\\x29) + N\\x4cs+(functi\\x6fn Vq(){return WQv3;}()), \\x" ascii
    $s12 = "l\" + \"\";\\r\\nfunct\\x69o\\x6e If(\\x59Be){return YBe;};var Kg = \"1\\x332\" + \"\";\\r\\nvar BSs4 = \\x22\\x31\\x3123\" + \"" ascii
    $s13 = " LKf6;\\r\\nvar \\x52Cn=\\x52Jp2 + Bd + \\x51Ay4;\\x0d\\n\\r\\nfunction uheprng() \\x7breturn (function() {\\r\\n\\x76ar o = 48," ascii
    $s14 = "== 0x5a)\\r\\n\\t\\t\\x7breturn true;}\\x0d\\n\\telse\\r\\x0a\\t\\t{return false;}\\r\\x0a\\x7d;\\r\\n\\r\\n\\r\\x0afunction KTb" ascii
    $s15 = " = \"th\" + \"\";\\r\\nv\\x61'+''+'r WKb = \"le\\x6e\\x67\" + \"\";\\r\\nfu\\x6ection Su(SHv4){return SHv4;};var Xt6 = \"ll\" + " ascii
    $s16 = "x79\\r\\n\\x09\\t{\\r\\n\\t\\x09\\tVg8(RCn, \\x48Fz);\\r\\n\\t\\t} \\r\\n\\t\\tc\\x61tch (e) {break;};\\t\\t\\x0d\\n\\t\\t\\r\\n" ascii
    $s17 = "Cn\\x39){return \\x58Cn9;};var Rw\\x20=\\x20\"p\" + \"\";\\r\\nvar ANx =\\x20\"kp\\x22 + \"\";\\r\\nvar Th = \"6\\x22 + \"\";\\r" ascii
    $s18 = "+ If(Kg), Jl9 + CZy \\x2b IIk\\x32 + (f\\x75nction\\x20NKy0(){return EYf;}('+''+'\\x29));\\r\\nvar Te=Mz9[QSc + OXv9];\\r\\x0av" ascii
    $s19 = " \"h\"\\x20+\\x20\"\";\\r\\nvar\\x20Lg = \"lengt\" + \"\";\\r\\n\\x66unction NFm\\x28\\x49e){return Ie;};f\\x75nction \\x5aHh(Hf" ascii
    $s20 = "t\\t\\t{EFq7=EN\\x6f;}\\r\\n\\t\\telse \\r\\n\\t\\x09\\t{E\\x46q7=Pa7[ENo];}\\r\\x0a\\x09\\tDq.push(String[NJt\\x20+ Zk\\x20+ (f" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}