rule sig_20160802_2428e7414f8ede9b693b432257c85ed4 {
  meta:
    description = "datamaliciousorder - file 20160802_2428e7414f8ede9b693b432257c85ed4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55f756142c8cdc7669f3bd495ff70ba8e1575b1db21a6e8d1a2bb945572a6b1f"

  strings:
    $s1  = "    var aYt4 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "unction\\x20RTo\\x32(Xh1){return Xh1;};var Lr8 = \"//t\\x6f\" + \"\";\\r\\nvar Jo7 = \"http:\"\\x20+ \\x22\";\\r\\nvar MSc5 = \"" ascii
    $s3  = " Pe[QS\\x63 + \\x28function F\\x54j(){return \\x4fXv9;}())]; O\\x50j++)\\r'+''+'\\n{\\r\\n\\ttry \\r\\x0a\\t{\\r\\n\\t\\tvar Sy" ascii
    $s4  = "6b;\\r\\n\\t}\\r\\n\\tc\\x61tch (e\\x29 {WScript\\x5b\\x44Kp + Zl1 + \\x45s7](1000); continue;};\\r\\n}\\x20w\\x68\\x69le\\x20" ascii
    $s5  = "\\x0d\\nSq[160]=255;\\r\\n\\t\\x0d\\n\\tv\\x61r HFz=\\x6eew Array();\\r\\n\\tfor (var O\\x50j=6938 - 6938; OPj <\\x20Tf0[JQu\\x2" ascii
    $s6  = "turn DHf1 /* y\\x20 */;\\x0d\\n};\\r\\n\\r\\n\\r\\n\\x66unction V\\x4f\\x797(\\x44Hf1 /* y  \\x2a/)\\r\\n{\\r\\n\\x09if (DHf1[0]" ascii
    $s7  = "\\r\\n\\t\\t\\tSy[RFc4 + Hg0(Yj0)](Qg(Oi0), ERb[OEq6++ % ERb[QSc \\x2b OXv9]], false);\\x0d\\n\\t\\t\\tSy[TTv(HXb)](\\x29;\\r\\n" ascii
    $s8  = "gt\" + \"\";\\r\\nfunction Qg(Bt4){retu\\x72n Bt\\x34;};var Oi0 = \"\\x47\\x45T\" + \\x22\"\\x3b\\r\\nfun\\x63tion Hg0(Ww){retur" ascii
    $s9  = "Lz){r\\x65turn Lz;};var El9 = \"et\" \\x2b \"\";\\r\\nvar\\x20DZz = \"rs\\x22 + \"\\x22;\\r\\x0avar WBt = \"Cha\" + \"\";\\r\\nv" ascii
    $s10 = "return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x0" ascii
    $s11 = "+'unction TTv(Yk){return Yk;};v\\x61r H\\x58b = \"send\"\\x20+\\x20\"\"\\x3b\\r\\nvar \\x45Qk9 = \\x22h\"\\x20+ \"\";\\r\\nvar L" ascii
    $s12 = ";var\\x20Vv = \"O\" +\\x20\"\\x22;\\r\\n\\x66unctio\\x6e V\\x723\\x28Pz8){return Pz8;};var V\\x6a = \"D\" + \"\";\\r\\nvar Oe3 =" ascii
    $s13 = "s\" + \"\"\\x3b\\x0d\\nvar Z\\x57l = \"Res\" + \"\"\\x3b\\r\\nvar Ub = \"w\\x72ite\" + \"\";\\x0d\\n\\x66unction BA\\x6e(Xz3){re" ascii
    $s14 = "x63ti\\x6f\\x6e Cn2()\\x7breturn O\\x58\\x769;}())]; OPj++)\\r\\n\\t{\\r\\n\\t\\tvar EFq7=Tf0[MOs3 + (f\\x75nction O\\x79(){retu" ascii
    $s15 = "tur\\x6e NLs;}()) + RGl2+Hh, UI\\x6b+(function VEd(){return Uf;}()) + (function Rz(){re\\x74u\\x72n J\\x654;}(\\x29)+JFw(EVb) + " ascii
    $s16 = "return YBe;};var Kg \\x3d \"132\" \\x2b \\x22\";\\r\\nvar B\\x53s4 = \"1123\" + \"\\x22;\\r\\nvar \\x4dz9=(BSs4 + \\x49f(Kg)\\x2" ascii
    $s17 = "0xef\\x63\\x38249d;\\r\\n};\\x0d\\x0aretu\\x72n m\\x61sh;\\r\\n}\\r\\n\\r\\n\\x76ar \\x50e=[QAy4 + WNj7 + C\\x4fz + Ra + (functi" ascii
    $s18 = "unctio\\x6e AMj0(){return N\\x688;}\\x28))\\x20+ Fa0 \\x2b \\x41Sj](RJp2, Ya);\\r\\n\\t\\tARt[HIk\\x5d()\\x3b\\r\\n\\t\\x0d\\n" ascii
    $s19 = "22\";\\r\\nvar EGw = \"ll\" + \"\\x22;\\r\\nvar Mj = \"lllll\" + \"\";\\r\\nfunction Oq(P\\x660){return Pf0;\\x7d;function SGv(K" ascii
    $s20 = "9]-2] <\\x3c 16 | DH\\x661[\\x44Hf1[QSc\\x20+\\x20OXv\\x39]-1] << 24;\\t\\r\\n\\tDHf1[(function Pq(){return EOp4;}()) + Uj](HFz[" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}