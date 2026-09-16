rule sig_20160802_6408e8b501fbcbe05b5084860089f799 {
  meta:
    description = "datamaliciousorder - file 20160802_6408e8b501fbcbe05b5084860089f799.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df05a3c7a09fe8bedafb7c29d1ccaa0f7ce34e73d2eb2d65febaca2b38ea8414"

  strings:
    $s1  = "    var aTUq0 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "\\r\\n\\t\\t\\x76\\x61r \\x41Rt=WScript[(functi\\x6fn\\x20SSq(){return Rp1;}(\\x29) + Ym\\x35\\x20+ \\x57r6 + S\\x4bu](Oe\\x33+V" ascii
    $s3  = "{return HPu\\x39;}())+Re1 + CNe2+DBs6(D\\x55m)];\\r\\nvar Ba5=WScript[Rp1 + Ym5 + Wr6 + SKu](YDx4 +\\x20A\\x6c + \\x28func\\x74i" ascii
    $s4  = "n\\r\\x0a\\x76ar GRx5\\x3d1;\\r\\nvar DAe=2;\\r\\nvar Ya=3\\x3607 - 3605;\\r\\nvar UMc=\"437\"\\x3b\\r\\n\\r\\nva\\x72 ERb=[SUf" ascii
    $s5  = " - 9\\x3731;\\r\\nPa7[255]=\\x316\\x30;\\r\\n\\x09\\r\\n\\tvar Dq=new Array();\\r\\n\\x09var Og=\"\";\\r\\n\\x09var ENo; var EFq" ascii
    $s6  = "6++ % ERb[QSc\\x20+ OXv9]], false);\\r\\n\\t\\t\\tSy[TTv(HXb)]();\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tif (S\\x79.readystate < (-" ascii
    $s7  = "\\x29;\\x0d\\n \\x20  WH\\x790[Dk + (fu\\x6ection CUl0(){return JPu;}()) +\\x20(function XIf8\\x28){return JGp\\x32;}())](Ly(DHf" ascii
    $s8  = "\\x2016 | DHf1[DHf1[QSc +\\x20OXv9]-1]\\x20<<\\x2024;\\t\\r\\n\\t\\x44H\\x661[(\\x66unction Pq(){return EOp4;}()) + Uj](HFz[QSc " ascii
    $s9  = "ngt\" + \"\";\\r\\nfunction Qg(Bt4){retu\\x72n Bt\\x34;};var Oi0 = \"\\x47\\x45T\" + \\x22\"\\x3b\\r\\nfun\\x63tion Hg0(Ww){retu" ascii
    $s10 = "{return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x" ascii
    $s11 = "'+'unction TTv(Yk){return Yk;};v\\x61r H\\x58b = \"send\"\\x20+\\x20\"\"\\x3b\\r\\nvar \\x45Qk9 = \\x22h\"\\x20+ \"\";\\r\\nvar " ascii
    $s12 = "};var\\x20Vv = \"O\" +\\x20\"\\x22;\\r\\n\\x66unctio\\x6e V\\x723\\x28Pz8){return Pz8;};var V\\x6a = \"D\" + \"\";\\r\\nvar Oe3 " ascii
    $s13 = "ns\" + \"\"\\x3b\\x0d\\nvar Z\\x57l = \"Res\" + \"\"\\x3b\\r\\nvar Ub = \"w\\x72ite\" + \"\";\\x0d\\n\\x66unction BA\\x6e(Xz3){r" ascii
    $s14 = "y + IIk2 + (functio\\x6e \\x4eKy0(){retur\\x6e\\x20EYf;}()));\\r\\nvar Te=Mz9[QSc + OXv9];\\x0d\\x0ava\\x72 NVd=(Mj + (function " ascii
    $s15 = " + (\\x66unction\\x20Cn2()\\x7bretur\\x6e O\\x58\\x769;}())\\x5d; OPj++)\\x0d\\x0a\\t{\\r\\n\\t\\tvar EFq7=Tf0[MOs3 + (function " ascii
    $s16 = "x09{EFq7=ENo\\x3b}\\r\\n\\t\\x09else\\x20\\r\\n\\t\\t\\x09{\\x45\\x46q7=Pa7[EN\\x6f];}\\r\\n\\t\\tDq.push(String[Hy8 + \\x49\\x5" ascii
    $s17 = "3dSq[EFq7]\\x3b}\\r\\x0a\\t\\tHFz[Mc0(L\\x6d) + (function Eo6()\\x7breturn Xe1;}()'+''+')](EN\\x6f);\\r\\n\\t};\\r\\n\\t\\r\\n" ascii
    $s18 = "5tur\\x6e CZi\\x38;}()),\\x20Zs5 + \\x54e1 + Su(\\x4dSl) + Xt6);\\r\\nvar \\x55Wy4=Pe0[QSc + (function LBy(){return OXv9\\x3b}(" ascii
    $s19 = "ion AMj0(){return Nh8;}(\\x29) + Fa0 + ASj](R\\x4ap2,\\x20Ya\\x29;\\r\\n\\t\\tA\\x52t\\x5bHIk]();\\r\\n\\t\\r\\n\\t\\tvar HFz=KT" ascii
    $s20 = "n Er8\\x28){return R\\x4d\\x734;}()) + VJk5\\x20+ RV\\x79(JGm3\\x29]);\\r\\n\\t\\tARt[\\x4eAe0 + PJh + MTj4]=1 * 0\\x3b\\r\\n\\t" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}