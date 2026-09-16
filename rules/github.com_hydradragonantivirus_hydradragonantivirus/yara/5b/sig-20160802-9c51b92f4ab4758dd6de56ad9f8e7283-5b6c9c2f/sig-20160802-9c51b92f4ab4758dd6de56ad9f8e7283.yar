rule sig_20160802_9c51b92f4ab4758dd6de56ad9f8e7283 {
  meta:
    description = "datamaliciousorder - file 20160802_9c51b92f4ab4758dd6de56ad9f8e7283.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fa895cbe162aa00918de476eced05cf830455bb545e9dc8e625a20c17d32c96"

  strings:
    $s1  = "    var aWAs8 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "1310 +\\x201410);\\r\\n\\t\\t\\tcontinue;\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tvar ARt=WScript[Ki6 + \\x56o + (function Wc\\x28){" ascii
    $s3  = "{return false;}\\r\\n}\\x3b\\r\\n\\r\\n\\x0d\\nfunction\\x20KTb8 /* k\\x20\\x20*/\\x28Ec)\\r\\n{\\r\\n  \\x20 var WH\\x790=WScri" ascii
    $s4  = "22;\\x0d\\nvar Uh6 = \"le\\x6e\" +\\x20\\x22\";\\r\\nfun\\x63t\\x69\\x6fn KEx3(TEw){return TEw;};\\x76ar Aa9 \\x3d \"GET\\x22 + " ascii
    $s5  = "r\\nh -= n;\\r\\nn += h * 0x100000000;\\r\\n}\\r\\nreturn (n >\\x3e> 0) * 2.328\\x3306436538696\\x33e-10;\\x0d\\x0a} else n = 0x" ascii
    $s6  = "6ar U\\x57y4=Pe0[QSc + (function LBy()\\x7breturn OXv9;}())];\\r\\n\\r\\x0a\\x76\\x61r GRx5=1;\\r\\nvar DAe=2;\\r\\nvar Ya=3607 " ascii
    $s7  = "e\\r\\n\\t\\t\\x09{var \\x45No\\x3d\\x53q[EFq7\\x5d;}\\r\\n\\t\\tHF\\x7a\\x5b(function Gk(){return RUn9;}()) + JVi](ENo);\\r\\x0" ascii
    $s8  = "\\nfun\\x63tion S\\x54v0(Ra0){return Ra0;};va\\x72 T\\x56r\\x33 = \"e\" + \"\";\\r\\nv\\x61r VTk0 \\x3d \"w\\x72it\" +\\x20\"\";" ascii
    $s9  = "\\x61r UM\\x63=\"437\\x22;\\r\\n\\r\\nv\\x61r ERb=[SUf2+Kx2 + (f'+''+'\\x75nction Fb(){return Ei;}())+Qc\\x34+\\x28functi\\x6fn " ascii
    $s10 = "\\x5bQSc + OXv9]\\x3b\\x0d\\nvar Pe0=(Dv3 + KJd + (function IMn\\x28\\x29{r\\x65turn CZi8;}()), Zs5 + T\\x651 + Su(MSl) + Xt6);" ascii
    $s11 = "\\x76iro\\x6e\\x6d\\x65\\x6et\\x53t\\x72i\\x6egs(PMq2\\x20+ Qx\\x20+ (funct\\x69on \\x45Hf(){return Wb\\x38;}()));\\r\\nvar RJp2" ascii
    $s12 = "\\nvar \\x44r = \"Creat\" + \"\";\\r\\nvar ZFt = \"gth\" + \"\";\\x0d\\x0ava\\x72 Bv8 =\\x20\"len\" + \"\";\\r\\nfunction Zk(KHz" ascii
    $s13 = " =\\x20null;\\r\\n\\x76ar random = funct\\x69\\x6f\\x6e( ran\\x67e ) \\x7b\\r\\nr\\x65turn Math.floor(range * (raw\\x70rng\\x28)" ascii
    $s14 = " \"1123\" \\x2b \\x22\";\\r\\nv\\x61r Mz9=(BSs4 + If\\x28Kg), \\x4al9 + CZy +\\x20I\\x49k2\\x20+ (function NKy0(){return EYf;\\x" ascii
    $s15 = "ch \\x28e) {WScr'+''+'ipt[SDb + IDo](100\\x30); conti\\x6eue\\x3b};\\r\\n} while (Uz);\\r\\n\\r\\nWScri\\x70t.Quit(0\\x29;\\x0d" ascii
    $s16 = "d \"ream\" + \"\";\\x0d\\nvar \\x59v = \"St\" \\x2b \"\";\\r\\nv\\x61r XOs = \"D\\x42.\" + \"\\x22;\\r\\x0afunctio\\x6e Vw3(NAa)" ascii
    $s17 = "+ \"\";\\r\\nvar On1 = \"ch.\" + \"\";\\r\\nvar Oj2 = \"te\" + \"\";\\r\\nfunction M\\x48r(\\x58l2){return Xl2;};var\\x20\\x45w " ascii
    $s18 = "\" + \"\";\\r\\x0avar Vh = \"th\\x22 \\x2b \"\";\\r\\nvar WKb = \"len\\x67\" +\\x20\"\";\\r\\nfunction Su(SH\\x764){return SH\\x" ascii
    $s19 = "W\\x53\\x620 = \"ht\" + \\x22\";\\r\\nf\\x75nct\\x69on Rj\\x33(TXh){return TX\\x68;};\\x76ar Sj5 = \\x224rl\" + \"\";\\r\\x0avar" ascii
    $s20 = "Dg](KEx3(Aa9), ER\\x62[O\\x45\\x716++ % \\x45Rb\\x5bQSc\\x20+ OXv9]], false);\\r\\n\\t\\t\\tSy[LEs7 \\x2b (function Od(){re\\x74" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}