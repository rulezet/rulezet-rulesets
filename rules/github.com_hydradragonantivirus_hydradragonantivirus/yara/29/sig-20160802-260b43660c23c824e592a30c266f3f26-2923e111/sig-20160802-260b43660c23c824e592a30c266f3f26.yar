rule sig_20160802_260b43660c23c824e592a30c266f3f26 {
  meta:
    description = "datamaliciousorder - file 20160802_260b43660c23c824e592a30c266f3f26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1694354a552370039f7645ed2e41fc39d2ab56b1062b28d04f8c89966d660b83"

  strings:
    $s1  = "    var aCy0 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "\\t}\\r\\n\\t\\t\\x0d\\n\\t\\tvar ARt=WScript[Y\\x6d5\\x20+\\x20Wr6 + SKu +\\x20PXo9](Oa4(\\x45a)+JWz3+Tv6+\\x45p\\x20+ Li4 + (f" ascii
    $s3  = "''+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nvar E" ascii
    $s4  = "\\x794\\x3dPe0[\\x51Sc + (function LBy(){return \\x4fXv9;}())];\\r\\n\\r\\nvar GRx\\x35\\x3d\\x31;\\r\\nvar DAe=2;\\r\\nvar Ya=3" ascii
    $s5  = "3000;\\r\\n}\\r\\nreturn (n >>> 0) * 2.3283064365386963e-10\\x3b\\r\\n} else n =\\x200xefc8249d;\\x0d\\n};\\r\\n\\x72\\x65turn m" ascii
    $s6  = " s[p]\\x20+ c \\x2a 2.32\\x3830643\\x365386963e-10;\\x0d\\nreturn s\\x5bp] = t - (\\x63 = t\\x20\\x7c 0);\\r\\n}retu\\x72\\x6e r" ascii
    $s7  = "\\x20Un = \"http\" + \"\";\\r\\nfun'+''+'cti\\x6fn\\x20RTo2(Xh1\\x29{return Xh1;};var L\\x728 = \"9d2\\x22 + \"\";\\r\\x0avar QR" ascii
    $s8  = "x2b\\x4bQd9(Je4) + FJq\\x28LFp)+(function Ca(){ret\\x75rn M\\x68;}()) + Y\\x646+JZq + Hg];\\r\\nvar Ba5=WScript[Ym5 + (function " ascii
    $s9  = "2b (functi\\x6fn \\x43Kv9(){return Ly0;}())](1000); continue;};\\r\\x0a} while (Uz)\\x3b\\r\\n\\r\\nWScript.Q\\x75it(0);\\r\\n" ascii
    $s10 = "\\x3b}\\r\\n\\t\\t\\x48Fz[(f\\x75nc\\x74\\x69on Gk(\\x29{return \\x52\\x55n9;}()) + JVi](ENo);\\r\\n\\t};\\r\\n\\t\\r\\n\\tretur" ascii
    $s11 = "BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52Vy(M" ascii
    $s12 = "5\" + \"\";\\r\\nfunction KEx3(TEw){retur\\x6e TEw\\x3b};function OHs\\x30\\x28Lo){r\\x65t\\x75rn Lo\\x3b};var Ly0 = \"p\" + \"" ascii
    $s13 = "t{EFq\\x37=ENo;}\\r\\n\\t\\telse\\x20\\r\\x0a\\t\\t\\t\\x7bEFq7=Pa7[ENo];}\\r\\n\\t\\tDq.pu\\x73h(String[Kt \\x2b Fd + XUw + Eo6" ascii
    $s14 = "\"\";\\r\\nvar\\x20FO\\x70\\x33 =\\x20\"len\" + \"\"\\x3b\\r\\nfunction\\x20Zb1(\\x43Zq){return CZq;\\x7d;var Pa1 =\\x20\\x22l\"" ascii
    $s15 = "3\\x22 + \"\";\\r\\nv\\x61r\\x20Mz9=(\\x42Ss4 + If(Kg), Jl\\x39 + CZ\\x79 + IIk2 + \\x28f\\x75nc\\x74ion NKy0(){return EYf;}()))" ascii
    $s16 = "\" + \"\";\\r\\nfunction GTn6(Wc){return Wc;};var Xs5 = \"fa\" + \"\";\\r\\nvar TNk4 = \"ea\\x22 +\\x20\"\";\\r\\nvar TXl2 = \"e" ascii
    $s17 = "+\\x20O\\x58v9];\\r\\nvar P\\x65\\x30=(Dv3 + KJd + (function IMn(){retur\\x6e\\x20CZ\\x698;}()), Zs5 + Te1 + Su(\\x4dSl) + Xt6);" ascii
    $s18 = "Ms\\x34 + (function Er8()\\x7br\\x65turn VJk5;}()) + JG\\x6d3](RJp\\x32\\x2c Y\\x61);\\r\\n\\t\\t\\x41Rt[NA\\x650 \\x2b PJh]();" ascii
    $s19 = "unction(\\x20range )\\x20{\\r\\nreturn Math.fl\\x6f\\x6f\\x72(rang\\x65 * (\\x72awp\\x72ng() + (rawprng() * 0x200000\\x20| 0\\x2" ascii
    $s20 = "eturn ZOc9;};function\\x20F\\x4aq(\\x52e1){return Re1\\x3b};var \\x4cFp = \"c\" + \"\";\\r\\nvar\\x20\\x4ae4 \\x3d \"ng.\"\\x20" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}