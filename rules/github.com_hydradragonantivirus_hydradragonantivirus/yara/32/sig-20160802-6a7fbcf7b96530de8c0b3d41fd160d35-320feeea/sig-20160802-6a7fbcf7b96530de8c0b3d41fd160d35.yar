rule sig_20160802_6a7fbcf7b96530de8c0b3d41fd160d35 {
  meta:
    description = "datamaliciousorder - file 20160802_6a7fbcf7b96530de8c0b3d41fd160d35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01566848ebd85e4cd3b5db473bd381ac55372e3f9dafcbffb7d2d5f886213600"

  strings:
    $s1  = "    var aZi = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x7" ascii
    $s2  = "\\x31000); \\x63ontinue;}\\x3b\\x0d\\n} while (U\\x7a);\\r\\n\\r\\nWScript.Quit(0);\\r\\n\\r\\x0af\\x75\\x6ect\\x69\\x6fn \\x42K" ascii
    $s3  = "\\x617[254]=19363 - 9731;\\r\\nPa\\x37[255]=160;\\r\\n\\x09\\r\\n\\tvar Dq=new Array();\\r\\x0a\\tvar Og=\"\"\\x3b\\r\\n\\t\\x76" ascii
    $s4  = "x100000000;\\r\\n}\\r\\nreturn (n >>> 0) * \\x32.3283\\x306436538\\x36963e\\x2d1\\x30;\\r\\n} else n = 0x\\x65f\\x638249d;\\r\\n" ascii
    $s5  = "= 1\\x37688\\x363 * s[p] + c * 2.328306\\x3436\\x35386963e-10;\\r\\nreturn s[p] \\x3d \\x74 - (c = t |\\x200);\\r\\n}return rand" ascii
    $s6  = "\\x2f/w\" + \"\";\\x0d\\nfunction Kx\\x32(\\x45i){return Ei;};var S\\x55f2 \\x3d \"http\" + \"\";\\r\\nvar \\x4cc = \"7\" + \"\"" ascii
    $s7  = "\\x38+PXh1+RAr+JIa \\x2b (function Ew(){return \\x56s;}(\\x29) + Yy1+H\\x711+TNk4(TXy), (function RGl2(){return Gr4;}()) + \\x28" ascii
    $s8  = "6cl;\\r\\nv\\x61r ran\\x64om = functio\\x6e( range )\\x20{\\r\\nreturn \\x4dath.\\x66\\x6coor(range *\\x20\\x28rawprng() + (rawp" ascii
    $s9  = "74ion I\\x69(){return TEd\\x3b}()) + Zf+Hh\\x2bVUg + RUf+Cp + \\x49Ht+(\\x66un\\x63tion Wc6(\\x29\\x7breturn HPu9;}()\\x29\\x2bR" ascii
    $s10 = "e\" + \"\";\\r\\nfunction DLr5(Bx7){retur\\x6e Bx7\\x3b};function Yj(\\x4b\\x661){re\\x74u\\x72n Kf1\\x3b};var Sh = \"p\" + \"\"" ascii
    $s11 = "n Gx0;}())\\x20+ KGo]\\x3d\\x47R\\x785\\x3b \\r\\n\\t\\tA\\x52t[Ub](Sy[ZW\\x6c + (fun\\x63tion Er8(){return R\\x4ds4;}()) + \\x5" ascii
    $s12 = "x30 = \"l\\x65n\" + \\x22\\x22;\\r\\nfun\\x63ti\\x6fn Ck9\\x28KF\\x6a){return KFj;}\\x3bvar Br\\x35\\x20= \"TP\" + \"\";\\r\\nva" ascii
    $s13 = "tp\" + \"\";\\r\\nvar Gr\\x34 = \"ht\" + \"\";\\r\\nf\\x75nction TN\\x6b4(X\\x735){return Xs5;};var TXy\\x20\\x3d \"pppb\" + \\x" ascii
    $s14 = "x66\\x30[JQu(Q\\x53c) + (fu\\x6e\\x63tion Cn2(){return OXv9;}())]; OPj++)\\r\\n\\t{\\r\\n\\t\\tv\\x61r EFq7=T\\x660[MOs3 + (func" ascii
    $s15 = " SSq(){return\\x20JHu8;}())]((function GOk(){return Zk;}()) + Qk1 + U\\x4al\\x20+ Z\\x59i);\\r\\x0avar Mz=Ba5.Expa\\x6edEnvir\\x" ascii
    $s16 = "= \\x221123\" + \"\";\\r\\nvar Mz9=(BSs4 \\x2b If(Kg), Jl9 +\\x20CZy\\x20+ IIk2 + (function NKy0(){\\x72etur\\x6e EYf;}(\\x29));" ascii
    $s17 = "{return Tl8;};var Xe1 = \"h\" \\x2b \"\";\\r\\nvar Lm = \"pu\\x73\\x22\\x20+\\x20\"\";\\r\\nvar Rt\\x20= \"At\"\\x20+ \"\";\\x0d" ascii
    $s18 = "+(\\x66unction GNn(){return FYs\\x31;}())+Rj3(Sj5)+WSb0+(func\\x74ion Ry\\x30(){return\\x20Qq;}()), Kx2(SUf2\\x29+Kg3+QRy5 + ZZs" ascii
    $s19 = "on L\\x694\\x28){return VTk0;}())+\\x49h2 + G\\x54\\x67 +\\x20XHb0);\\x0d\\n\\t\\tAR\\x74[E\\x6c]();\\r\\n\\t\\tA\\x52t[(functio" ascii
    $s20 = "Ru + Sp +\\x20\\x43k9(L\\x770) \\x2b Br5];\\r\\n\\r\\n\\x66or \\x28var OPj=0; OPj < P\\x65[QSc + (function FTj(){return OXv9;\\x" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}