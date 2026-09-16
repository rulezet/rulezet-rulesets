rule sig_20160802_091dbaae2e9e0a1ac44bcc8e3a69f73a {
  meta:
    description = "datamaliciousorder - file 20160802_091dbaae2e9e0a1ac44bcc8e3a69f73a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8de9923661c0c4dc6ef9c73c8c2987638717ef92c9a40e8378cd544e3c0969f2"

  strings:
    $s1  = "    var aJCm8 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = ">> 0;\\r\\nh -= n;\\r\\nn +=\\x20h * 0x100000000;\\r\\n}\\r\\nreturn (n >>> 0)\\x20* 2.3\\x328306436\\x353869\\x363\\x65-10;\\r" ascii
    $s3  = "=0; OPj < Pe[QSc\\x20+ (function FTj(){return OX\\x769;}())]; \\x4fPj++)\\x0d\\x0a\\x7b\\r\\x0a\\ttry \\r\\n\\t{\\r\\n\\t\\tvar " ascii
    $s4  = "Rx5=1;\\x0d\\x0avar DAe\\x3d2;\\r\\nvar Ya=3607 - 3605;\\r\\x0avar UMc=\"437\";\\r\\n\\r\\nvar ERb\\x3d[SUf2+\\x4bx2 + (fun\\x63" ascii
    $s5  = "new Array()\\x3b\\r\\n\\x09for (var O\\x50j=6938 - 6938; O\\x50j <\\x20Tf0[JQ\\x75(QSc) + (function Cn2(){\\x72eturn OXv9;}())];" ascii
    $s6  = "Xy + Aw);\\r\\n\\t\\tbrea\\x6b;\\r\\n\\t}\\r\\n\\t'+''+'catch (e) {WScript\\x5bDKp + Zl\\x31 +\\x20Es7](1000); continue;};\\r\\n" ascii
    $s7  = "\\x28)),\\x20Zs5 \\x2b Te1 +\\x20Su(MSl\\x29 + Xt6);\\x0d\\nvar UWy4=Pe0[QSc\\x20+ (function LBy(){return OXv9;}())];\\r\\n\\r" ascii
    $s8  = "\\r\\nvar Gz = 672168\\x3b\\r\\nva\\x72 Id=N\\x56d[QSc \\x2b OXv9];\\r\\nvar Pe0=(Dv'+''+'\\x33 + KJd + (function IMn(){retu\\x7" ascii
    $s9  = "8y0=W\\x53cript[B\\x5ab(Wc\\x29 + PMq2(EIk) + YFe + (fu\\x6ection Tv(){ret\\x75rn \\x4aHu8;}())](Oe3+\\x56\\x723(Vj)+(function G" ascii
    $s10 = "+)\\r\\n\\t{\\r\\n\\t\\t\\x52E\\x74\\x32=(REt2 + D\\x48f1[\\x4fPj]) % 0x100\\x3000000;\\x0d\\n\\t};\\x0d\\n\\tif (REt2 != Cm\\x2" ascii
    $s11 = "ion PMq2(Qx){return Qx;}\\x3bv\\x61r \\x4aHu8 = \"ect\" + \\x22\";\\r\\nva\\x72 YFe = \"bj\" + \"\";\\r\\n\\x76\\x61r E\\x49k = " ascii
    $s12 = "ngt\" + \"\";\\r\\nfunction Qg(Bt4){retu\\x72n Bt\\x34;};var Oi0 = \"\\x47\\x45T\" + \\x22\"\\x3b\\r\\nfun\\x63tion Hg0(Ww){retu" ascii
    $s13 = " (function NKy0(){ret\\x75r\\x6e EYf;}()));\\x0d\\x0avar Te=Mz9[QSc + OXv9];\\r\\nvar NVd=(M\\x6a\\x20+ \\x28function Oi5(){retu" ascii
    $s14 = "{return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x" ascii
    $s15 = "'+'unction TTv(Yk){return Yk;};v\\x61r H\\x58b = \"send\"\\x20+\\x20\"\"\\x3b\\r\\nvar \\x45Qk9 = \\x22h\"\\x20+ \"\";\\r\\nvar " ascii
    $s16 = "6 + \\x31484) | DHf1[DHf1[QSc + OXv9]\\x2d2] << 16 \\x7c DHf1[DHf1[QSc +\\x20OXv9]\\x2d1] << 24;\\t\\r\\n\\t\\x44Hf1[(function P" ascii
    $s17 = ";\\r\\nvar Re1 = \"/f\" + \"\";\\r\\nvar HPu9 = \".68\" + \"\";\\r\\nfunction LFp(As3){return As\\x33;}\\x3bvar Jr = \"9\" + \"" ascii
    $s18 = "nvar Ba5=WScr\\x69pt[Wc + (function PXo9(\\x29{return EIk;}()) + YFe + (function SSq(){return JHu\\x38;\\x7d())\\x5d((fu\\x6ecti" ascii
    $s19 = ")\\r\\n\\t{\\x0d\\n\\t\\tva\\x72 EFq7\\x3dTf\\x30\\x5bMOs3 +\\x20(functio\\x6e\\x20Oy(){return AXy6;}()) + Rt](OPj);\\r\\n\\t\\t" ascii
    $s20 = " + \"\";\\r\\nvar OOh = \"h\" + \\x22'+''+'\";\\r\\nvar Ud8\\x20\\x3d \"gt\" + \"\";\\x0d\\nvar FOp3 = \"len\" + \"\";\\r\\nfunc" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}