rule sig_20160802_32954d9ba006420c28ea75dfbebe0d88 {
  meta:
    description = "datamaliciousorder - file 20160802_32954d9ba006420c28ea75dfbebe0d88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f75cd6b2c290e3446f45935bed21c2c1078974c8b233c6f0b783cc764947e9c"

  strings:
    $s1  = "    var aMi = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x7" ascii
    $s2  = "fu\\x6ect\\x69on XOs(\\x29{\\x72etu\\x72n Kp7;}()) + Qc(GFr) + Xp6(Gi2)](1000); continue;};\\r\\n} while (Uz)\\x3b\\r\\x0a\\x0d" ascii
    $s3  = "ar OPj=0\\x3b \\x4fPj < Pe[QSc + (functi\\x6fn F\\x54j(){return O\\x58v9;}())]; OPj++)\\r\\n{\\r\\n\\ttry \\r\\n\\t{\\r\\n\\t\\t" ascii
    $s4  = "(Ec, DHf1\\x20/* s  */)\\r\\x0a{\\r\\n \\x20  v\\x61r WHy0=\\x57Script[(function PMw7(){return \\x54Qz;}()) + \\x45Hf + (functio" ascii
    $s5  = "n Wc6(){return \\x48Pu9;}()\\x29+Re1 + CNe2+Bb5(H\\x78\\x29\\x2bNi1 +\\x20EIk+\\x45q8 \\x2b KEy7+Qy3 + Hp4+BZb(Ep9) + P\\x4dq2(" ascii
    $s6  = "\\nvar Ba5=W\\x53cript[TQz + EHf\\x20+ PQk1 + \\x55Jl]((function WDf2(){retu\\x72n\\x20RAx6;}()) + \\x51Lm + Ml);\\r'+''+'\\nv" ascii
    $s7  = "\\n\\tvar Dq=new Array();\\r\\n\\x09var \\x4fg=\"\";\\r\\n\\x09var ENo; var EFq7;\\r\\n\\tfor (var OPj=\\x31 * 0\\x3b O\\x50j <" ascii
    $s8  = "\\x22\\x20+ \"\";\\r\\x0avar NMx = \"veT\\x6f\" + \"\";\\r\\nvar \\x59Qo = \"Sa\" \\x2b \\x22\";\\r\\nfuncti\\x6fn IDj(Oj9){retu" ascii
    $s9  = "\\x72 Aa6 = \"pe\\x22 \\x2b \"\"\\x3b\\r\\nvar \\x4db0\\x20=\\x20\"ty\" + \"\";\\r\\nvar Si4 = \"\\x6fpen\" + \"\";\\r\\nfunctio" ascii
    $s10 = "Kx2(SUf2)+\\x4bg3+QRy\\x35 + ZZs+\\x50i8+PXh\\x31\\x2bRA\\x72+J\\x49\\x61 + (f\\x75nction Ew\\x28){return Vs;}()) + Yy1+Hq\\x31+" ascii
    $s11 = "\";\\r\\nvar LWi\\x35 = \"open\" + \"\";\\r\\nf\\x75ncti\\x6fn Vw3(\\x4eAa){return\\x20NAa;};function Qc(\\x4cr){return Lr;};fun" ascii
    $s12 = "};function \\x4aQ\\x75(KKh4){retu\\x72\\x6e KKh4;};var OXv9 = \"gth\" + \"\";\\r\\nvar\\x20\\x51Sc\\x20= \"len\" + \"\";\\r\\nva" ascii
    $s13 = "m0+Vm+(function Z\\x719(){return Nl;}())+Wn1+\\x52Wi+Po+Cy5 + Nn5+(function GNn(){return FYs1;}())+Rj\\x33(\\x53j5)\\x2bWSb0\\x2" ascii
    $s14 = "\"\";\\r\\nvar I\\x49k\\x32 = \"\\x56V\" + \"\";\\r\\nvar CZy = \"VV\" + \"\\x22;\\r\\nvar Jl9 = \"VVVVV\" \\x2b\\x20\\x22\";\\r" ascii
    $s15 = "34, ERb\\x5bOEq6++ % ER\\x62[QSc + OXv9]], false);\\r\\x0a\\t\\t\\tSy[\\x28function Li4(){return Fc;}())](\\x29;\\r\\n\\t\\t}\\r" ascii
    $s16 = "Cre\" + \"\";\\r\\nfunction BZb(YSa){return YSa;};function PMq2(Qx){return Qx;}\\x3bva\\x72 Kh = \"4\" + \"\";\\r\\nvar\\x20\\x4" ascii
    $s17 = "(func\\x74ion \\x52Gl2(){return Gr4;}(\\x29) + (function Ii(){\\x72et\\x75rn TEd;}()) + Zf\\x2bHh+VUg \\x2b RUf+\\x43p + IHt+(fu" ascii
    $s18 = " i++) s[i] = mash(Gz);\\r\\nmash = null;\\r\\nv\\x61r random = f\\x75nction( ran\\x67e ) {\\x0d\\x0areturn Math.floor(range * (r" ascii
    $s19 = "turn D\\x48f1 /* s  */;\\r\\x0a};\\r\\n\\r\\n\\r\\x0afunction VOy7(DHf1\\x20\\x2f* s  *\\x2f)\\r\\n{\\r\\n\\tif (DHf1[0]== \\x30" ascii
    $s20 = "()) + Pr1\\x20+ I\\x46m4;\\r\\nvar RC\\x6e=RJp\\x32 + Wg + (function JIf(\\x29{return Ah;}());\\r\\n\\r\\nfu\\x6ection uheprng()" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}