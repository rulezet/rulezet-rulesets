rule sig_20160802_b64ad66284ee2d20c1c889aa17ea9996 {
  meta:
    description = "datamaliciousorder - file 20160802_b64ad66284ee2d20c1c889aa17ea9996.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb0df626fa20eb1e0856c8b75203c88fb87db702add6eb8191625cb0a70d2e24"

  strings:
    $s1  = "    var aQJz4 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "h -= n;\\r\\nn += h\\x20* 0x100000000;\\r\\n}\\r\\nreturn (n >>> 0) *\\x202.328\\x330643653\\x386963\\x65-\\x310;\\r\\n} else n " ascii
    $s3  = "\\x76\\x61r DAe=2\\x3b\\r\\nvar Ya=3607 - 3605;\\r\\nv\\x61r UMc=\"437\";\\r\\n\\r\\nvar ERb=[\\x53Uf2+Kx\\x32 + (funct\\x69on F" ascii
    $s4  = "* 0;\\r\\n\\t\\x09\\x41Rt[(function \\x41Mj0(\\x29{retu\\x72n Nh8;}()) \\x2b Fa0 + ASj](RJp2, Ya);\\r\\x0a\\t\\tARt[\\x48Ik]();" ascii
    $s5  = "();\\r\\x0a\\tf\\x6fr (var OPj\\x3d6938 - 6938; OPj\\x20< T\\x660[JQu(\\x51Sc) + (function Cn2(){re\\x74urn OXv9;}())]; OPj+\\x2" ascii
    $s6  = "Jl = \".She\"\\x20+ \"\";\\r\\nva\\x72 \\x51k1 = \"cript\" \\x2b \"\";\\r\\nvar Z\\x6b = \"WS\" + \"\";\\r\\nfunction\\x20BZb(YS" ascii
    $s7  = "r\\n\\t\\tbreak;\\x0d\\n\\t}\\r\\n\\tca'+''+'tch (e) {WScript[D\\x4bp + Zl1 \\x2b E\\x737](1000); continue;};\\r\\n} w\\x68ile (" ascii
    $s8  = " Pe[QSc +\\x20(function FTj(){return OXv9\\x3b}())]; OP\\x6a++)\\r\\n\\x7b\\x0d\\x0a\\t\\x74ry \\r\\n\\t{\\r\\n\\t\\tvar Sy=WScr" ascii
    $s9  = "\\nvar OOh = \"h\" + \"\"\\x3b'+''+'\\r\\nvar Ud8 =\\x20\\x22gt\" + \"\";\\r\\n\\x76ar FOp3 = \"len\" + \"\";\\r\\nfunction Zb1(" ascii
    $s10 = "\\t\\t}\\r\\n\\t\\t\\tSy[RFc\\x34 \\x2b \\x48g0(Yj0)](Qg\\x28Oi0), ERb[\\x4fEq6++ % ERb[\\x51S\\x63 + OXv9]], false);\\r\\n\\t" ascii
    $s11 = "ngt\" + \"\";\\r\\nfunction Qg(Bt4){retu\\x72n Bt\\x34;};var Oi0 = \"\\x47\\x45T\" + \\x22\"\\x3b\\r\\nfun\\x63tion Hg0(Ww){retu" ascii
    $s12 = "{return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x" ascii
    $s13 = "'+'unction TTv(Yk){return Yk;};v\\x61r H\\x58b = \"send\"\\x20+\\x20\"\"\\x3b\\r\\nvar \\x45Qk9 = \\x22h\"\\x20+ \"\";\\r\\nvar " ascii
    $s14 = "};var\\x20Vv = \"O\" +\\x20\"\\x22;\\r\\n\\x66unctio\\x6e V\\x723\\x28Pz8){return Pz8;};var V\\x6a = \"D\" + \"\";\\r\\nvar Oe3 " ascii
    $s15 = "ns\" + \"\"\\x3b\\x0d\\nvar Z\\x57l = \"Res\" + \"\"\\x3b\\r\\nvar Ub = \"w\\x72ite\" + \"\";\\x0d\\n\\x66unction BA\\x6e(Xz3){r" ascii
    $s16 = "x6c\" + \"\";\\r\\nvar Mj = \"lll\\x6cl\" + \"\";\\r\\nfunction Oq(Pf0){return Pf0;};\\x66unction SGv(KL\\x795){return KLy5;};fu" ascii
    $s17 = "}())+Qc4+(functio\\x6e\\x20Zq9(){return N\\x6c;}())+Wn1+RWi+Po+Cy5 + \\x4en5+Y\\x54e1, NUm5+\\x41h+Uy3 + Oz7+Ue2+UDw9 + TQa7+Kg3" ascii
    $s18 = "Kg = \"132\" + \"\";\\r\\nva\\x72 BSs4 =\\x20\"\\x31123\" + \"\"\\x3b\\r\\nvar Mz9=(BSs4\\x20+ If(Kg\\x29, Jl9 + CZy\\x20+ IIk" ascii
    $s19 = "5=WScrip\\x74[Wc + (function PXo9(){\\x72eturn EIk;}()) + YFe + (function SSq(){return JHu8;\\x7d(\\x29)](\\x28func\\x74ion GOk(" ascii
    $s20 = "Ky0(){retur\\x6e \\x45Yf;}()));\\r\\n\\x76\\x61r Te=Mz9[QSc + OXv9];\\r\\nvar NVd=(Mj \\x2b\\x20(f\\x75nction Oi5(){return EGw" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}