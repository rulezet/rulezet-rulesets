rule sig_20160802_9549ca5b170179687f6f4b90383166bf {
  meta:
    description = "datamaliciousorder - file 20160802_9549ca5b170179687f6f4b90383166bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8866a52896e95b1747320329a9efbaa3e50b90f1f7b9092715ead12e5cca6b44"

  strings:
    $x1  = "    var aURh0 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "+''+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nvar " ascii
    $s3  = " (n >>> 0) * 2.3\\x32830643\\x365\\x338\\x36963\\x65-10;\\r\\n} else n =\\x200\\x78e\\x66c8249d;\\r\\n};\\r\\nreturn\\x20mash;" ascii
    $s4  = "] + c * 2.3283064\\x33653\\x386963e-10;\\r\\n\\x72etur\\x6e s[p] = t - (c = t | 0\\x29;\\r\\n}return random;}())\\x3b};\\r\\n\\r" ascii
    $s5  = "DAe=2;\\r\\nvar Ya=3\\x3607 -\\x203605;\\x0d\\nvar U\\x4dc=\"437\";\\r\\n\\r\\nvar ERb='+''+'\\x5bSUf2+Kx2 + (function Fb(){ret" ascii
    $s6  = "\\t\\x09Ba5[ILh6\\x20+ \\x45t1](RCn + (function JYj5(){return IDj;}())\\x20+ Oj9);\\r\\n\\t\\tb\\x72eak;\\r\\n\\t}\\r\\n\\tca\\x" ascii
    $s7  = "\\x72\\x28){\\x72eturn Yy;}()) + Gx\\x30]\\x28Sy[(function Xz3(){\\x72eturn \\x51\\x61;}\\x28)) + H\\x732 + S\\x610]\\x29;\\r\\n" ascii
    $s8  = "\\n\\t};\\x0d\\n\\x09\\x69f (REt2 !=\\x20Cm)\\x20{return [];}\\x3b\\r\\n\\t\\r\\n\\t\\x72etur\\x6e DHf1 /* k  */;\\r\\x0a\\x7d;" ascii
    $s9  = "\\x29)+Q\\x634+(f\\x75nction\\x20Zq9(){\\x72eturn Nl\\x3b}())+Wn1+RWi+Po+C\\x795 + Nn5+(function GNn(){return FYs1;}())+\\x52j3" ascii
    $s10 = "65\" + \"\";\\r\\nfunction KEx3(TEw){retur\\x6e TEw\\x3b};function OHs\\x30\\x28Lo){r\\x65t\\x75rn Lo\\x3b};var Ly0 = \"p\" + \"" ascii
    $s11 = "(BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52Vy(" ascii
    $s12 = "\"\";\\r\\x0avar Sr6 = \"ABCD\" + \\x22\";\\r\\nvar Pj0 = \"xe\" + \"\";\\r\\nvar Kk5 = \".e\" \\x2b\\x20\"\\x22;\\r\\nfunc\\x74" ascii
    $s13 = " BZb(YSa)\\x7bre\\x74urn YSa;};f\\x75nction PMq2(Qx\\x29{return Qx;\\x7d;var O\\x748 = \"ct\" + \"\";\\r\\nvar JHu8 \\x3d \"eObj" ascii
    $s14 = "r Gz = 672\\x316\\x38;\\r\\nvar Id=N\\x56\\x64[QSc + OXv9];\\r\\nvar Pe0=(Dv3 + KJd +\\x20\\x28fu\\x6ection IMn(){return CZi8\\x" ascii
    $s15 = "){return SHv4;};var Xt6 = \"ll\\x22 +\\x20\"\";\\r\\nvar MS\\x6c = \\x22\\x6cl\" + \"\";\\r\\nvar\\x20Te\\x31 = \"lllll\" + \"\"" ascii
    $s16 = "W\\x53\\x620+(func\\x74ion Ry0(){return Qq;}())\\x2bNAm9, MSc5 + QRy5+RTo2(Lr\\x38)+Un+C\\x6c8+Ae+Yy1 \\x2b Ri5+(function Xl\\x3" ascii
    $s17 = "+ Te1 + S\\x75(\\x4dSl) \\x2b Xt6);\\r\\nvar UWy4=Pe0[QSc + (\\x66unction LBy(){return \\x4f\\x58\\x769;}())];\\r\\n\\r\\nvar GR" ascii
    $s18 = "[Jm + Fe + \\x4aHu8 + Ot8](Dy6(Ea)+JWz3+T\\x766\\x2b\\x28\\x66unction \\x44\\x59h0(){return E\\x70;}()) \\x2b\\x20(functi\\x6fn " ascii
    $s19 = "return K\\x4bh4;};var OX\\x769 = \"gth\" + \"\";\\r\\nv\\x61r Q\\x53c\\x20=\\x20\\x22le\\x6e\\x22 + \\x22\";\\r\\nva\\x72 EYf = " ascii
    $s20 = "n( range ) {\\r\\n\\x72eturn Math.floo\\x72(range * \\x28rawprng() + (rawprng() * \\x30x\\x3200000 | 0) *\\x201.11022302'+''+'46" ascii

  condition:
    uint16(0) == 0x200a and
    1 of ($x*) and 4 of them
}