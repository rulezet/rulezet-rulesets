rule sig_20160802_1526551184c6f5cb281e33cb18ce8db1 {
  meta:
    description = "datamaliciousorder - file 20160802_1526551184c6f5cb281e33cb18ce8db1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa40d53706d775d7fdf9e522fd08aaa037c46f1ca7b9675813d6a811e7b52733"

  strings:
    $s1  = "    var aRSv = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "n Rz(){\\x72eturn Je4;}())+JFw(EVb)\\x20+ FJq+Bb5(GHx)];\\r\\nvar Ba5=WScript[Wc0 + (function P\\x58o\\x39(){\\x72etur\\x6e EIk;" ascii
    $s3  = "turn (n >>> 0) * \\x32.\\x33\\x328306\\x34\\x3365\\x3386963e-10;\\r\\n} el\\x73e n = 0xefc824\\x39d;\\r\\n};\\r\\nre\\x74urn mas" ascii
    $s4  = "0]\\x3d25\\x33;\\r\\nSq[9632\\x5d=254;\\r\\nSq[160]=2\\x355;\\r\\x0a\\t\\r\\n\\tva\\x72 HFz=new Array();\\r\\n\\tfor \\x28var OP" ascii
    $s5  = "(Oi0),\\x20ERb[OEq6++ % ERb[QSc + OXv9]], false);\\r\\n\\t\\t\\tSy[TTv(HXb)]\\x28);\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\ti\\x66 (" ascii
    $s6  = "\\x74ion Oy(){return A\\x58y\\x36;}()) + Rt\\x5d(OPj);\\r\\n\\t\\tif (EFq7\\x20< (4 \\x2a 32))\\r\\n\\t\\t\\t{v\\x61\\x72 ENo=EF" ascii
    $s7  = "\\x20+ \"\";\\r\\nvar Mz9=(BSs4\\x20+ If(Kg\\x29,\\x20Jl9 + CZy\\x20+ IIk2 + (funct\\x69on NKy0\\x28){return EY\\x66;}())\\x29" ascii
    $s8  = "gt\" + \"\";\\r\\nfunction Qg(Bt4){retu\\x72n Bt\\x34;};var Oi0 = \"\\x47\\x45T\" + \\x22\"\\x3b\\r\\nfun\\x63tion Hg0(Ww){retur" ascii
    $s9  = "x20Lu7);\\r\\n  \\x20 WHy0[NAc3 + BAn(Nq)]=DA\\x65;\\r\\n '+''+' \\x20 WHy0[WB\\x74 + XEe(DZ\\x7a) + (functi\\x6fn\\x20Bl0(){ret" ascii
    $s10 = "on PMq2(Qx){return Qx;}\\x3bv\\x61r \\x4aHu8 = \"ect\" + \\x22\";\\r\\nva\\x72 YFe = \"bj\" + \"\";\\r\\n\\x76\\x61r E\\x49k = " ascii
    $s11 = "Es1, Pm \\x2b RKw + COs7 + Ru + Sp];\\r\\n\\r\\n\\x66or (var O\\x50j=0; \\x4f\\x50\\x6a \\x3c Pe[QSc + (function FTj(){retu\\x72" ascii
    $s12 = "= \"gt\" + \"\";\\r\\nvar FOp3 = \\x22'+''+'len\" + \"\";\\r\\x0a\\x66unction Zb1\\x28CZq){return CZq;};var Pa1 = \"V\" + \"\";" ascii
    $s13 = "Lz){r\\x65turn Lz;};var El9 = \"et\" \\x2b \"\";\\r\\nvar\\x20DZz = \"rs\\x22 + \"\\x22;\\r\\x0avar WBt = \"Cha\" + \"\";\\r\\nv" ascii
    $s14 = "return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x0" ascii
    $s15 = "s\\x65\\r\\n\\x09\\t\\t{var ENo=\\x53q[EFq7];}\\r\\n\\t\\tHFz[Mc\\x30(Lm) + (functi'+''+'on Eo\\x36(){return Xe1;}())](ENo);\\r" ascii
    $s16 = "turn Mh;};var FJq = \"z\" + \"\";\\r\\nvar EVb = \"/1\" + \"\";\\r\\nvar Je4 = \"om\" + \"\";\\r\\x0ava\\x72 Uf = \".c\" + \"\";" ascii
    $s17 = " UJl = \".Sh\\x65\" + \"\";\\r\\n\\x76a\\x72 Qk1 = \"cript\\x22 + \"\";\\r\\nvar\\x20Zk = \"WS\" + \"\";\\r\\nfuncti\\x6fn BZb(Y" ascii
    $s18 = "\";\\r\\x0avar Vh =\\x20\"\\x74h\" + \"\";\\r\\nva\\x72 WKb = \"len\\x67\" +\\x20\"\";\\r\\nfunctio\\x6e S\\x75\\x28SHv4){return" ascii
    $s19 = "MSc5 + QRy5+\\x52To2(\\x4cr8)+U\\x6e+Cl8+Ae, Yy1 \\x2b Ri5+(functi\\x6fn Xl2(){return \\x44t6;}\\x28))\\x2bOj2+Xs5 +\\x20\\x4cq3" ascii
    $s20 = "Fe\\x20+ (fun\\x63tion SS\\x71(){ret\\x75\\x72n \\x4aHu\\x38\\x3b}())]\\x28(function\\x20GOk(){return Zk;}()) + Qk\\x31 + UJl + " ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}