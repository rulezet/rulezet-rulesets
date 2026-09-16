rule sig_20160802_02373e6c050470a977fad37290964314 {
  meta:
    description = "datamaliciousorder - file 20160802_02373e6c050470a977fad37290964314.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "466bc7ec3f5eb97d972721a3035a2d83cf3a3d28eea5012a25c5880350dd5042"

  strings:
    $x1  = "    var aUCe = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = ">>> 0;\\r\\nh -= n;\\r\\nn += h * 0x100000000;\\r\\n}\\r\\nret\\x75rn (n >>> 0)\\x20* 2.3283064\\x3365386\\x39\\x363e-10;\\r\\n}" ascii
    $s3  = "Ly0)]\\x28-1310 + 1410);\\r\\n\\t\\t\\tc\\x6fn\\x74i\\x6eue;\\r\\n\\t\\t}\\r\\n\\t\\x09\\r\\n\\t\\tvar AR\\x74=WScript[QFp\\x35 " ascii
    $s4  = "''+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nvar E" ascii
    $s5  = "r Ya=36\\x307 - \\x33605;\\r\\x0avar UM\\x63=\"437\";\\r\\n\\r\\nvar ERb=['+''+'\\x53Uf2+DFm0+Vm+(function Zq9(){r\\x65t\\x75rn " ascii
    $s6  = "for (v\\x61r OPj\\x3d6938 - 6938; \\x4fPj < \\x54f0[\\x4aQu(Q\\x53c)\\x20+ (function Cn2\\x28)\\x7breturn\\x20O\\x58v9;}())]; OP" ascii
    $s7  = "n\\t\\x09else\\r\\x0a\\t\\t\\t{v\\x61r \\x45\\x4eo=Sq[E\\x46q7];}\\r\\n\\t\\x09\\x48Fz[(function Gk(){return RUn9;}()) + JVi](EN" ascii
    $s8  = "x2b\\x20AXa + Rl3+TGx6\\x20+ Yh+KQd9(Je4) + FJq(LF\\x70)+(f\\x75nction Ca\\x28){return Mh;}()) + Yd6+IJh];\\r\\nvar Ba5=WScript[" ascii
    $s9  = "n\\x74inue;};\\r'+''+'\\n} while (Uz);\\r\\n\\r\\n\\x57Script.Q\\x75it\\x280);\\r\\n\\r\\nfunction BKw(DHf1 /\\x2a k  */)\\r\\x0" ascii
    $s10 = "\\r\\x0a\\t\\tARt[MP\\x6b5\\x5d=GRx5; \\x0d\\n\\t\\tARt[(func\\x74ion \\x58D\\x72(){return Yy;}\\x28))\\x20+ Gx\\x30](Sy[(f\\x75" ascii
    $s11 = "\\tif (ENo < 12\\x38)\\x20\\r\\n\\t\\x09\\t{EFq7=ENo;}\\r\\n\\t\\telse \\r\\n\\t\\x09\\t{EFq7=Pa7[E\\x4eo];}\\r\\n\\t\\tDq.push(" ascii
    $s12 = "ction KQd9(ZOc9){re\\x74u\\x72n \\x5aOc9;};function\\x20FJq(Re\\x31){return Re1;};var \\x4c\\x46p =\\x20\"8\" + \\x22\\x22;\\r" ascii
    $s13 = "BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52Vy(M" ascii
    $s14 = "d\\nvar Ep3 \\x3d \"43\" + \"\";\\r\\x0av\\x61r Vh = \"th\" + \"\";\\r\\nv\\x61r W\\x4bb = \"leng\" + \"\";\\r\\nf\\x75nction Su" ascii
    $s15 = "x22\";\\r\\nvar B\\x53s\\x34 = \"1\\x3123\" + \"\";\\r\\nvar M\\x7a9=(BS\\x734 + If(Kg)\\x2c \\x4al9\\x20+ CZy + IIk2 + (functio" ascii
    $s16 = "+ LV\\x64\\x29;\\r\\n\\x76\\x61\\x72\\x20R\\x4ap\\x32=\\x4dz + (fu\\x6ectio\\x6e PMw7(){\\x72etu\\x72n IFh;}()) + Z\\x6f7 + (fun" ascii
    $s17 = "1u = \":/\" + \"\";\\r\\nvar Un'+''+' = \\x22h\\x74tp\" + \"\"\\x3b\\r\\nfunction RTo2(Xh1\\x29{return \\x58h1;};va\\x72 Lr8 = " ascii
    $s18 = "x368\\x3b\\r\\nvar Id=NV\\x64\\x5bQSc + OXv9];\\r\\nvar Pe0=(Dv3 + KJd + \\x28\\x66un\\x63tion IMn(){return CZi8;\\x7d()), Zs5 +" ascii
    $s19 = "tu\\x72n U\\x78;}()) + RJp \\x2b SPs0](Oa4(Ea)+JWz3+Tv6+Ep + Li4 + (function TBc(){retu\\x72n Bw8;}()));\\r\\n\\t\\t\\x41Rt[ESh " ascii
    $s20 = "5\" + \"\";\\r\\nfunction KEx3(TEw){retur\\x6e TEw\\x3b};function OHs\\x30\\x28Lo){r\\x65t\\x75rn Lo\\x3b};var Ly0 = \"p\" + \"" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}