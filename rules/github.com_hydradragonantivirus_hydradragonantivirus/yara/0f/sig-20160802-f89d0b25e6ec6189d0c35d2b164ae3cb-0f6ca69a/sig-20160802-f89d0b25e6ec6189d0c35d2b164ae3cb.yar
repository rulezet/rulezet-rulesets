rule sig_20160802_f89d0b25e6ec6189d0c35d2b164ae3cb {
  meta:
    description = "datamaliciousorder - file 20160802_f89d0b25e6ec6189d0c35d2b164ae3cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b14fdf72d4bcc6e61fa8f640e961860f7cc656f2d6e0946489f58bb488581d7a"

  strings:
    $s1  = "    var aUy = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x7" ascii
    $s2  = "x32(Kh)];\\r\\nvar Ba5\\x3dWScript[TQz + E\\x48f + PQk1 \\x2b UJl]((function WDf2(){re\\x74u\\x72n RAx6;}()) \\x2b QLm + Ml)'+''" ascii
    $s3  = "8(Ec, D\\x48f1 /* s  *\\x2f)\\r\\n{\\x0d\\n  \\x20 var WH\\x790=WScript[(function PMw7(){retu\\x72n TQz;}())\\x20+ EHf + (funct" ascii
    $s4  = "Script[TQz\\x20+ EHf + (functio\\x6e GOk(){return PQk\\x31;}()) + \\x55J\\x6c](Pe[OP\\x6a]);\\r\\n\\t\\tbreak\\x3b\\r\\n\\t}\\x0" ascii
    $s5  = "\\x22\\x20+ \"\";\\r\\x0avar NMx = \"veT\\x6f\" + \"\";\\r\\nvar \\x59Qo = \"Sa\" \\x2b \\x22\";\\r\\nfuncti\\x6fn IDj(Oj9){retu" ascii
    $s6  = "\\x72 Aa6 = \"pe\\x22 \\x2b \"\"\\x3b\\r\\nvar \\x4db0\\x20=\\x20\"ty\" + \"\";\\r\\nvar Si4 = \"\\x6fpen\" + \"\";\\r\\nfunctio" ascii
    $s7  = "\\n{\\x0d\\n\\x20  \\x20\\x76ar WHy0=WScr\\x69pt\\x5b(function Tc(){\\x72etur\\x6e TQz;}()) + EHf + PQk1 + U\\x4al](\\x50Dv+\\x5" ascii
    $s8  = "\\x620+MHu, Kx2(SUf2\\x29+Kg3+Q\\x52y5 + ZZ\\x73+Pi8+P\\x58\\x681+\\x52Ar\\x2b\\x4aIa + \\x28function \\x45w(){return Vs;}()) + " ascii
    $s9  = "\\n\\x09\\x09\\t\\x09W\\x53cript[\\x4bp7 + (funct\\x69on Wt6(\\x29{return GFr;}()) + \\x47i2](1000);\\x0d\\x0a\\t\\t\\t}\\r\\n" ascii
    $s10 = "\";\\r\\nvar LWi\\x35 = \"open\" + \"\";\\r\\nf\\x75ncti\\x6fn Vw3(\\x4eAa){return\\x20NAa;};function Qc(\\x4cr){return Lr;};fun" ascii
    $s11 = "\" + \"\";\\r\\nfuncti\\x6fn WQh(J\\x6d){return Jm;};\\x66unc\\x74\\x69o\\x6e VWu1\\x28SPi8){r\\x65turn\\x20SPi8;};function Vz6" ascii
    $s12 = "va\\x72 \\x58O\\x66 = \\x22Ob\"\\x20+ \"\";\\r\\nvar NFm = \"eate\\x22 + \"\\x22\\x3b\\r\\nvar Bv = \"Cr\\x22 +\\x20\"\"\\x3b\\r" ascii
    $s13 = " \\x2b \"\";\\r\\nvar Tw = \"\\x52e\" + \"\"\\x3b\\r\\nf\\x75nc\\x74ion AJ\\x614\\x28Xj6){return Xj6;};funct\\x69on Yc9(G\\x6a){" ascii
    $s14 = "[SUf\\x32+DFm0+Vm+(function\\x20Zq9(){return Nl;}())+Wn\\x31+RWi+Po+Cy5 + Nn5+(function GNn(){return FYs1;}())+\\x52j\\x33(Sj\\x" ascii
    $s15 = "d[EX\\x66 + PSp + Lw0 + Br5 + LGb + VUs\\x31 + Sh, LJa + Xj + \\x4bEx3 + TEw + (functio\\x6e \\x5al\\x31(){return H\\x49z;}())];" ascii
    $s16 = "se \\r\\n\\t\\t\\t{EFq7=Pa7[ENo];}\\r\\n\\t\\t\\x44q.push(String[\\x57Qh(In) + VWu\\x31(KMf) + RJx +\\x20\\x56z6(Mi4\\x29](E\\x4" ascii
    $s17 = "t[\\x28fu\\x6ection X\\x4fs\\x28){r\\x65turn Kp7;}()) + Qc(GFr) + Xp6(Gi2)](1000); continue;};\\r\\n} while (\\x55z\\x29\\x3b\\r" ascii
    $s18 = "20+ Gs4 + Pa1);\\r\\nva\\x72\\x20Gz = 672168;\\r\\n\\x76ar Id=NVd[QSc + OXv9];\\r\\x0avar \\x50e0=(Dv3 +\\x20KJd + (function IMn" ascii
    $s19 = "Zi8;}()), Zs5 + Te\\x31 + S\\x75(MSl)\\x20+ Xt6);\\r\\nvar \\x55Wy4=Pe0[QSc \\x2b (function LBy(\\x29{ret\\x75rn\\x20OXv9;}())" ascii
    $s20 = " IIk2\\x20+ (\\x66unct\\x69on NKy\\x30(){ret\\x75rn EYf;}\\x28)));\\r\\nvar Te=Mz9[\\x51Sc + OXv9];\\r\\nvar NVd=(Mj + (function" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}