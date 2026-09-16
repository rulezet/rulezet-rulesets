rule sig_20160802_9a9824ecd25acb2c543ec9ee5e6525e7 {
  meta:
    description = "datamaliciousorder - file 20160802_9a9824ecd25acb2c543ec9ee5e6525e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f40fee6a2ee00e92df8ff0338edbaf0f7a7bfbfa2bc735290af319234969de6"

  strings:
    $s1  = "    var aKFo4 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "\\x47\\x6a0+(function Ii\\x28){return NLs;}()) + RGl\\x32+Hh+\\x55Ik];\\r\\nvar\\x20Ba5=WScript[(function XEd0(){return Ki6;}())" ascii
    $s3  = "\\t\\t\\tWScri\\x70t[SDb + IDo](-1310 + 1410);\\r\\n\\t\\t\\tcontinue;\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tv\\x61r ARt=WScript[K" ascii
    $s4  = "b\\r\\x0avar Uh6 = \"len\\x22 + \\x22\\x22;\\r\\nfunc\\x74i\\x6f\\x6e KEx3(TEw){return TEw;};v\\x61r Aa9 =\\x20\"GET\"\\x20+ \"" ascii
    $s5  = "\\nvar Y\\x61=360\\x37 - 36\\x305;\\r\\nva\\x72 UMc=\"437\";\\r\\n\\r\\nvar E'+''+'\\x52b=[SUf2+Kx2 + (function Fb(){\\x72e\\x74" ascii
    $s6  = "\\nfuncti\\x6fn Vg\\x38(Ec,\\x20DHf1\\x20/\\x2a\\x20k  */)\\r\\n{\\x0d\\n    var WHy0=WScript[Ki6 + \\x56\\x6f + VE\\x64 + (func" ascii
    $s7  = "\\x20+ \"\";\\r\\nva\\x72 \\x57Mp = \"pt\" + \"\\x22;\\r\\nvar XHp4\\x20= \"WScri\" + \"\";\\r\\nfuncti\\x6fn NMh(Yd6){return Yd" ascii
    $s8  = "+ \"\";\\r\\n\\x76ar\\x20\\x55d8\\x20= \"gt\" + \"\\x22;\\r\\nvar FOp\\x33 = \"\\x6cen\" + \"\";\\r\\nfunc\\x74ion Zb1(CZ\\x71" ascii
    $s9  = "(function \\x45Po(){re\\x74u\\x72n Wp;}())\\x20+ Xc6 + Zb1(YUc\\x29 + ZDo7\\x20+ Ol + HMr4\\x20+ TXe\\x38\\x20+ Gs4 + Pa1);\\r" ascii
    $s10 = "9+Qc4\\x2b(funct\\x69on Zq9\\x28){return\\x20Nl;}())+Wn1+RWi+P\\x6f+Cy5 + Nn5+(function GNn(){return FYs1;}(\\x29)+\\x52j3(Sj5" ascii
    $s11 = "WHy5 + G\\x6f(HXi6)]=1 * 0;\\x0d\\n\\t\\tARt\\x5b\\x48s\\x32 \\x2b AFy(S\\x610) + (funct\\x69on Ix6(\\x29{return ETx9;}()) +\\x2" ascii
    $s12 = " \"\";\\r\\nfunction DEk0\\x28Ja0\\x29{return Ja0;};functi\\x6fn\\x20P\\x4ah(\\x4dTj4){\\x72etur\\x6e MTj4;};va\\x72 RVy = \"e\"" ascii
    $s13 = "turn s[p] =\\x20t -\\x20(c = t | 0)\\x3b\\r\\n}r\\x65turn random;}());};\\r\\n\\r\\x0afunction Mash() {\\r\\nvar\\x20n = 0xefc82" ascii
    $s14 = "WSb0+H\\x75 + Ry0+VIf + Sc5+XCn9+SF\\x68 + To2+Jp1+(function WJf(\\x29{retur\\x6e Ja;}())+\\x53Ki9 + IKv+GAq, WS\\x620+Hu + Ry0+" ascii
    $s15 = "x367\\x32168;\\r\\nvar I\\x64\\x3dNVd[QSc + OXv9];\\r\\nvar Pe0=(Dv3 + KJ\\x64\\x20+ \\x28function IMn(){return C\\x5ai8;}()), Z" ascii
    $s16 = "2b \\x53u(MS\\x6c) + Xt6);\\r\\nvar UWy4=Pe0[QSc \\x2b (function LBy(){retu\\x72\\x6e\\x20OXv9;}())];\\r\\n\\r\\nvar GRx5=1;\\r" ascii
    $s17 = " + V\\x45d + (\\x66unction DAz1(\\x29{return KQd9\\x3b}())](XHp4 + (f\\x75ncti\\x6fn \\x59Dx4(){ret\\x75\\x72n WMp;}()) + Vz\\x3" ascii
    $s18 = "turn SHv4;};var Xt6 = \\x22VV\\x22 + \"\";\\r\\nvar\\x20MSl\\x20\\x3d \"VV\" + \"\";\\r\\n\\x76ar\\x20Te1 = \"VVVVV\" + \"\";\\r" ascii
    $s19 = "));\\r\\nvar RJp2=Mz + F\\x74 + Pz + YWf + FGa;\\r\\nvar RCn=RJp2 + Za + USw;\\r\\n\\r\\nfun\\x63t\\x69on \\x75hepr\\x6eg() {ret" ascii
    $s20 = "r\\nvar D\\x72 = \"Creat\" + \"\";\\r\\nvar ZFt = \"gth\" + \"\";\\r\\x0a\\x76ar\\x20Bv8 = \\x22len\" + \"\";\\r\\nfunction Zk(K" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}