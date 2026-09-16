rule sig_20160802_394a5207c1c021614a22b60986d744ff {
  meta:
    description = "datamaliciousorder - file 20160802_394a5207c1c021614a22b60986d744ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3aa0da42d61fd8a17068bdff6caa86d55163b1e0737dfb6b0f17f334d2b834c5"

  strings:
    $s1  = "    var aTl2 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "QSc + \\x28func\\x74ion L\\x42y(){return OX\\x769;}())];\\r\\n\\r\\n\\x76ar GRx5=1;\\r\\nvar\\x20DAe=\\x32;\\r\\x0avar Ya=36\\x3" ascii
    $s3  = "\\x4ek4(T\\x58y)+(function RGl2()\\x7breturn Gr4;}()) + (\\x66un\\x63tion Ii(){return\\x20TEd;}()\\x29 + Zf\\x2bHh+VUg + RUf+Hf" ascii
    $s4  = ") s[i] = mash(Gz);\\r\\nmash = null;\\r\\x0avar random =\\x20function( r\\x61nge )\\x20\\x7b\\r\\nreturn Math.floor(range * \\x2" ascii
    $s5  = "''+' \\x4fPj++)\\r\\n\\t\\x7b\\r\\n\\t\\tREt2=\\x28REt2 + DHf1\\x5bO\\x50j]) % 0x100000000;\\r\\x0a\\t};\\r\\x0a\\t\\x69f (REt2 " ascii
    $s6  = "ll\" + \"\";\\x0d\\n\\x76ar J\\x6c9 = \"lllll\" + \"\";\\r\\nfunction \\x49f(YBe){return YBe;};v\\x61\\x72\\x20Kg = \"132\" + \"" ascii
    $s7  = "Rh2\\x20+ E\\x724 + Uw + Zo\\x34 + G\\x58a4;\\r\\nvar RCn=RJp2 + RJ\\x7a(TCc1) + KZl(MIp);\\r\\n\\r\\n\\x66unction uheprng() {re" ascii
    $s8  = "x6a(Rm9) + (function JYj5(){r\\x65turn Zq;\\x7d(\\x29\\x29 + DOl0\\x20+ MIi1]);\\x0d\\n\\t\\tARt\\x5bOFl + BFf\\x38\\x20+ QNv2 +" ascii
    $s9  = "x20\\x2b\\x20OXv9]-2]\\x20\\x3c< 16 | DHf1[D\\x48f1[QSc\\x20\\x2b OXv9]-\\x31] << 24;\\x09\\r\\n\\x09DHf1\\x5bWXb(WBt) + (functi" ascii
    $s10 = "c3(RYk){return RYk\\x3b};var T\\x4bh = \"ode\" + \"\"\\x3b\\r\\nv\\x61\\x72 \\x4aLa = \\x22rC\" + \"\\x22;\\r\\nv\\x61r Nv = \"o" ascii
    $s11 = "3\\x306436\\x353869\\x363e-10;\\r\\n}\\x20e\\x6cse n = 0xefc\\x38249d;\\r\\n};\\r\\nreturn mash;\\x0d\\n}\\x0d\\x0a\\r\\nvar \\x" ascii
    $s12 = " Ep3 = \"4\\x33'+''+'\" + \"\";\\r\\nva\\x72\\x20Vh = \"th\" +\\x20\"\";\\r\\nvar WKb = \"leng\" + \"\";\\r\\nfunction Su(SHv4){" ascii
    $s13 = "Zc8);\\r\\n\\t\\tAR\\x74[(function XO\\x73(){return HXb;}())]();\\r\\n\\t\\tARt\\x5bTj4]=GRx'+''+'5; \\r\\n\\t\\tARt[ASj(Rq)\\x2" ascii
    $s14 = "s7 + Ru + Sp + Lw0 + Br5 +\\x20LGb + (function ST\\x736(){return VUs1;}())\\x20+\\x20X\\x6a(Sh), Te0 +\\x20OHs0 + Lo \\x2b Yp];" ascii
    $s15 = "retur\\x6e Qq;}(\\x29)+NAm9+\\x53j, QRy\\x35\\x20+ \\x5aZs\\x2b\\x50i8+PX\\x681+RAr+JIa\\x20+ (function Ew(){return V\\x73;}()) " ascii
    $s16 = "for\\x20(\\x76ar OPj=0; OPj < Pe[QS\\x63 + \\x28function FTj\\x28){return OXv9;}())]; OPj++)\\r\\n{\\r\\n\\ttry \\r\\n\\t{\\r\\n" ascii
    $s17 = "nvar Qq = \"de/\\x32\" \\x2b \"\";\\r\\nvar W\\x53b0 \\x3d\\x20\"e.\" + \"\";\\r\\nf\\x75nc\\x74ion Rj3(TXh){return TXh;};var Sj" ascii
    $s18 = "+ OXv9];\\r\\x0a\\x76ar Pe0=(Dv3 + \\x4bJd + (function IMn(){re\\x74urn \\x43Zi8;}()),\\x20Zs5 + Te1 + Su(MSl) + Xt6);\\r\\nvar " ascii
    $s19 = " + \"\";\\r\\nvar Yz4 = \"WSc\" + \"\";\\r\\nfunction BZb(YSa){return YS\\x61;}\\x3bfunction PMq2(Qx){re\\x74\\x75rn Q\\x78;};va" ascii
    $s20 = "= \"\\x6e\" + \"\"\\x3b\\r\\nvar NAe0 = \"ope\" + \"\"\\x3b\\r\\n\\x66u\\x6ection AFy(UWx3)\\x7breturn \\x55Wx3\\x3b};fun\\x63ti" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}