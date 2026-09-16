rule sig_20160802_0638ccc664f18ef062cb5e79696821b8 {
  meta:
    description = "datamaliciousorder - file 20160802_0638ccc664f18ef062cb5e79696821b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9593c8cb5382b8a2deab3998f3be469acf93fd93757b0c08cc4c19f5e5f9f91"

  strings:
    $s1  = "    var aIt6 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "}\\r\\nreturn (n >>> 0) * 2.\\x33283064365386963e-1\\x30;\\r\\n} else n = 0xefc8\\x324\\x39d\\x3b\\r\\n};\\r\\nretur\\x6e mash;" ascii
    $s3  = "963\\x65\\x2d10;\\r\\x0aret\\x75rn s[p] = \\x74 - \\x28c = t | 0);\\r\\n}retu\\x72n random;}());};\\r\\n\\r\\nfunction Mash()\\x" ascii
    $s4  = "c\\x61tch\\x20(e) {WScript\\x5bDUr7 +\\x20(fun\\x63tion Yk(){return\\x20\\x58Ea;}())]\\x281000); continue;};\\r\\n} while (Uz\\x" ascii
    $s5  = "\\r\\nfunction \\x4cr(Bl){return Bl;};\\x66unct\\x69on Dy6\\x28ZSn3){retu\\x72n ZSn3;};var Yv = \\x22en\" + \"\";\\r\\nvar XOs =" ascii
    $s6  = "\\x31\\x5b1]== 0x5a)\\r\\n\\x09\\t{\\x72eturn true;}\\r\\n\\t\\x65lse\\r\\x0a\\t\\t{return false;}\\r\\n};\\r\\n\\r\\n\\r\\x0afu" ascii
    $s7  = "\\nvar Mj = \"lllll\"\\x20+ \"\";\\r\\n\\x66u\\x6ection Oq(\\x50f0){return Pf0;\\x7d;functi\\x6fn SGv(KLy5)\\x7bretur\\x6e\\x20K" ascii
    $s8  = "\" \\x2b \"\";\\r\\nvar Tw = \"\\x52e\" + \"\"\\x3b\\r\\nf\\x75nc\\x74ion AJ\\x614\\x28Xj6){return Xj6;};funct\\x69on Yc9(G\\x6a" ascii
    $s9  = "N\\x4by0()\\x7breturn\\x20EYf;}(\\x29));\\r\\nvar\\x20Te=Mz9[QSc + OXv9\\x5d;\\r\\nvar NVd=(Mj + (function Oi5(){return E\\x47w;" ascii
    $s10 = "var Bz = \"pt.\" + \"\";\\r\\nvar Kr6 = \"ri\" + \"\";\\r\\nvar Yz4 = \"WSc\" + \"\"\\x3b\\r\\n\\x66unction BZb(YSa){ret\\x75\\x" ascii
    $s11 = "tion E\\x77(){r\\x65turn Vs;}()) + Yy1+\\x48q1+TNk4(TXy)+(funct\\x69on\\x20RGl2(){return Gr\\x34;}()) +\\x20(func\\x74ion Ii(){r" ascii
    $s12 = "n\" + \"\";\\r\\nfuncti\\x6fn WQh(J\\x6d){return Jm;};\\x66unc\\x74\\x69o\\x6e VWu1\\x28SPi8){r\\x65turn\\x20SPi8;};function Vz6" ascii
    $s13 = "x20Aa6 = \"pe\"\\x20+\\x20\"\";\\x0d\\nvar M\\x620 \\x3d \\x22ty\" + \"\";\\r\\nvar Si4 = \"o\\x70en\" + \"\";\\r\\nfunction Tf5" ascii
    $s14 = "1(CZq){return C\\x5aq;};var Pa1 = \"l\" + \"\";\\r\\nvar Gs4 = \"llll\\x6c\" + \"\";\\r\\nvar T\\x58e8 = \"ll\" + \"\";\\r\\nvar" ascii
    $s15 = " + Zo + \\x53d4(\\x50r1));\\r\\nvar \\x52Jp2=\\x4dz + Dv6 + IKb2(Cc) + R\\x4az(VBk) + VHo + (functi\\x6fn Ee3(){return Pd9;}());" ascii
    $s16 = "y \\r\\n\\x09{\\r\\n\\t\\tva\\x72 Sy=WS\\x63\\x72ip\\x74[(function SWb(){r\\x65t\\x75rn WPv;}()) + SSq +\\x20BZb(VV\\x6c\\x37)]" ascii
    $s17 = "DLr5];\\r\\n\\r\\nfor \\x28var OPj=0; OPj < \\x50e[QSc + \\x28f\\x75nction \\x46Tj(){return \\x4fXv9;\\x7d(\\x29)]; OPj++)\\r\\n" ascii
    $s18 = "var Pe=[TP\\x6c \\x2b (function STs6(){ret\\x75rn \\x51Lw0;}()) + X\\x6a(Br5) + LGb + VUs1 + Sh + Te0(Wj6), Yp + NRk1 + Kw + Od" ascii
    $s19 = "]=2\\x352;\\r\\n\\x53\\x71\\x5b-6592 + 677\\x30]=253;\\r\\nSq[9632]=254\\x3b\\r\\nSq[\\x3160]=255;\\x0d\\x0a\\x09\\r\\n\\tva\\x7" ascii
    $s20 = "r Gz = 672\\x31\\x368;\\r\\nvar Id=NVd\\x5bQSc + OXv9];\\r\\nvar Pe0=(\\x44v3 +\\x20KJd + (fu\\x6ection IMn(){return CZi8;}()), " ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}