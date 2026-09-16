rule sig_20160802_0c6314020322a8b360e459b9b341405e {
  meta:
    description = "datamaliciousorder - file 20160802_0c6314020322a8b360e459b9b341405e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "977fc2cb0c3d6056172eb5bed51e23313abb5621b935c2caf54fc5b4c321f91f"

  strings:
    $s1  = "    var aMh7 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "63a\\x74ch \\x28e) {WScript[DUr7 + (function Yk(){return XEa;}())](1000); continu\\x65;\\x7d\\x3b\\r\\n} while \\x28Uz)\\x3b\\r" ascii
    $s3  = "x6eue;\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tvar ARt=WScript[T\\x76 + (func\\x74io\\x6e UAq1(){return LVd;}()) + Uh8 + Ft0](PDv+R" ascii
    $s4  = "\\r\\nSq\\x5b9\\x3632]=254;\\r\\nSq[160\\x5d=255;\\r\\n\\t\\r\\n\\t\\x76ar HFz\\x3dnew Array();\\r\\n\\tfor (v\\x61r\\x20OPj=\\x" ascii
    $s5  = "\\x20\"\";\\r\\nvar GQc4 = \\x22/w\" + \"\";\\r\\nvar Fb\\x20= \":/\"\\x20+ \"\\x22;\\x0d\\nfunct\\x69on Kx2(Ei){return Ei;};var" ascii
    $s6  = "\\x7a3 + Zc8 + Tn \\x2b BXy);\\r\\n\\t\\tARt[XOs + Yv]();\\r\\n\\t\\x09ARt[Mb0 '+''+'+ (function Wh1(){\\x72eturn Aa\\x36;}\\x28" ascii
    $s7  = "\\r\\n\\t\\tDq.push(St\\x72ing[WQh(In) + \\x56Wu1(KMf) + R\\x4ax + Vz6(Mi4)]\\x28\\x45Fq7));\\x0d\\n\\t}\\x0d\\x0a\\t\\r\\n\\tO" ascii
    $s8  = "\\x22 + \"\";\\x0d\\nvar NMx = \"ve\\x54o\" + \"\";\\r\\nvar\\x20YQo = \"Sa\"\\x20+\\x20\"\";\\r\\nfunct\\x69on IDj(Oj9){return " ascii
    $s9  = "n   \\x20var \\x57Hy0\\x3dWScript\\x5bTv + (function GXf(){return LVd\\x3b}()) + Ml(\\x55h8) + Ft0](PDv\\x2b\\x52Xq+URy9+Xz3 \\x" ascii
    $s10 = "\\x5aq){return CZq;};var Pa1 = \"l\" + \"\";\\r\\nvar\\x20Gs4 = \"lllll\" \\x2b \"\";\\r\\nvar TXe8 = \"ll\" + \"\";\\r\\nv\\x61" ascii
    $s11 = "\\n\\t\\tREt2=\\x28REt2 + DH\\x661[OPj]) % 0\\x781\\x300000000;\\r\\n\\t};\\r\\n\\tif \\x28REt2\\x20!\\x3d Cm) {return [\\x5d;};" ascii
    $s12 = "\\x5aWp)+CRy4+SOm3+OCz5+UAm8\\x2bNUm5 + QTb2 + Rj3+MWq0 + (function UDw9(){return Th\\x3b}\\x28))+\\x45v8(A\\x4ex) + Rw+ISm, Kx" ascii
    $s13 = "n\" + \"\";\\r\\nfuncti\\x6fn WQh(J\\x6d){return Jm;};\\x66unc\\x74\\x69o\\x6e VWu1\\x28SPi8){r\\x65turn\\x20SPi8;};function Vz6" ascii
    $s14 = "e\\x22 + \"\";\\r\\nvar Tw =\\x20\"Re\" + \\x22\";\\r\\x0afu\\x6ection \\x41J\\x614(Xj6){return Xj6;};fun\\x63tion Yc9\\x28Gj)" ascii
    $s15 = "rn Vc;}()) + NLs+(f\\x75nction Vq(){return \\x57Qv\\x33;}()), SUf2+Er +\\x20(functi\\x6fn IHt\\x28){return FId;}(\\x29)+HZu+Vb+Y" ascii
    $s16 = "ar Pe=[(functio\\x6e ASq6(){return SDb\\x3b}()) + IDo + Fo + Us\\x31 \\x2b \\x53h + Wj6 + Z\\x71 + Ir1, Uh\\x36 + BEf + XHf\\x35" ascii
    $s17 = "20Su(MS\\x6c) + Xt6);\\r\\nva\\x72 UWy4=Pe0[QS\\x63 + (function LB\\x79(){r\\x65tu\\x72n OXv9;}(\\x29\\x29];\\r\\n\\r\\nvar GRx5" ascii
    $s18 = "19;\\r\\nPa7\\x5b\\x3253]=178;\\r\\nPa7[254]=\\x319363\\x20- 9731\\x3b\\r\\nPa\\x37[255]\\x3d160;\\r\\n\\t\\r\\n\\t\\x76\\x61r D" ascii
    $s19 = "0IIk2\\x20= \"ll\" + \"\";\\r\\nvar CZy = \"ll\"\\x20+ \"\";\\r\\nvar Jl9 = \"lll\\x6c\\x6c\\x22 + \"\";\\r\\nfunction If(YBe){r" ascii
    $s20 = "t4 = \"len\" + \"\";\\r\\nva\\x72 YKl6\\x20= \"h\" + \"\";\\r\\n\\x76ar Uj = \"gt\" +\\x20\"\";\\r\\nvar EOp4 = \\x22len\" \\x2b" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}