rule sig_20160802_d29dbfa1dcc6077b5ab543f6ac202705 {
  meta:
    description = "datamaliciousorder - file 20160802_d29dbfa1dcc6077b5ab543f6ac202705.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81c70b66bf3962db0c63548301909eb4d582bb6e09464e8c4c4bd50d20155dbf"

  strings:
    $s1  = "    var aYFt = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "x6e Vo;}\\x28))];\\r\\nvar Ba5\\x3dWScript[HPu9\\x20+ GCo + CNe2(AH\\x61)](P\\x58o9\\x20+ (functi\\x6f\\x6e SWb(){return Q\\x79" ascii
    $s3  = "av\\x61r UW\\x794=Pe0[QSc + (function LBy(){\\x72eturn OXv9;}())];\\r\\n\\r\\n\\x76\\x61\\x72 GRx5=1;\\r\\nvar DAe=2;\\r\\nvar Y" ascii
    $s4  = "}\\r\\x0a\\t\\tels\\x65\\r\\n\\x09\\x09\\t{var \\x45No=Sq[EF\\x71\\x37];}\\r\\n\\t\\tHFz[(function Gk(){return RUn9;}()) + \\x4a" ascii
    $s5  = "\\x22\"\\x3b\\r\\nvar Uh6 = \"l\\x65n\" \\x2b\\x20\"\";\\r\\nfu\\x6ec\\x74\\x69on KEx3(TEw){return TEw;}\\x3bvar Aa9\\x20= \"GE" ascii
    $s6  = "\\r\\nvar\\x20Dr = \"Creat\" + \"\";\\r\\nvar ZFt = \"gth\" + \"\"\\x3b\\x0d\\nv\\x61r Bv8 \\x3d \"len\" + \"\";\\r\\nfunction Z" ascii
    $s7  = "\\r\\nva\\x72 UMc\\x3d\"437\"\\x3b\\r\\n\\r\\nva\\x72 ERb=[SUf2+Kx2 + (fu'+''+'\\x6ection Fb(){return Ei;}())+Qc4\\x2b(\\x66unct" ascii
    $s8  = "\\nvar T\\x65=Mz9[QSc + OXv9];\\r\\nvar NVd=\\x28Mj + (function\\x20Oi5\\x28){return EGw;}()) + Dh5 + \\x43a8 +\\x20(functi\\x6f" ascii
    $s9  = "\\x63ript[HPu9 + GCo + AHa](TY\\x6a+\\x28\\x66\\x75nction G\\x69\\x32(){return Cc0\\x3b}())+W\\x74\\x36+XOs + \\x59v + Xf);\\x0d" ascii
    $s10 = " \"\";\\r\\nvar Ee = \"t\" + \"\"\\x3b\\r\\nv\\x61r Kf1 = \"b\\x6ae\\x63\" \\x2b \"\";\\r\\n\\x76ar Yj \\x3d \"\\x74eO\" + \"\";" ascii
    $s11 = "4\\x33\" + \"\";\\r\\n\\x76ar Vh = \"th\"\\x20+\\x20\"\";\\r\\nvar WKb = \"leng\\x22 + \\x22\";\\r\\nfunction Su(SHv\\x34){retur" ascii
    $s12 = "x20= \"ream\" + \"\"\\x3b\\r\\nvar\\x20Yv = \"St\"\\x20+ \"\";\\r\\n\\x76ar XOs = \"\\x44B.\" + \\x22\";\\x0d\\nfuncti\\x6fn Vw3" ascii
    $s13 = "r\\n\\t\\t\\t}\\r\\x0a\\t\\t\\x09\\x53y[IDg]\\x28KE\\x783(A\\x619), ERb[OEq6++ % ERb[QSc + OXv\\x39]], false);\\r\\n\\t\\t\\tSy" ascii
    $s14 = "\" + \"\";\\r\\nfunction DE\\x6b0(J\\x610){return Ja0;};func\\x74i\\x6fn\\x20PJ\\x68(MTj4\\x29{ret\\x75rn MTj4;};\\x76ar RVy = " ascii
    $s15 = "r\\nfu\\x6ection \\x53Tv0(Ra0){return Ra0;};v\\x61r \\x54V\\x723 = \"e\" + \"\";\\r\\n\\x76ar VTk0\\x20= \"\\x77rit\" \\x2b \"\"" ascii
    $s16 = "x0d\\nv\\x61r Qx = \"EMP\\x22 + \"\";\\r\\nvar Mq\\x32 = \"%T\" + \"\\x22;\\r\\nfun\\x63tion BZb(YSa){return YSa;\\x7d;var WMp =" ascii
    $s17 = "turn W\\x692\\x3b\\x7d())]\\x3b\\x0d\\n\\r\\x0afor (var OPj=0; \\x4fPj < Pe[QSc + \\x28function F\\x54j(){retu\\x72n O\\x58\\x76" ascii
    $s18 = " \\x3d \"1123\" +\\x20\"\\x22;\\r\\nva\\x72 Mz9=(BSs4 + If(\\x4bg), J\\x6c9 + CZy + \\x49I\\x6b2 \\x2b (function NKy0(){return E" ascii
    $s19 = "e-10;\\r\\x0aret\\x75rn s[p] = t\\x20- (c\\x20= t | 0);\\r\\n}return ran\\x64om;}());};\\r\\n\\r\\nfunction\\x20Mash() {\\r\\nva" ascii
    $s20 = "turn Wp;}(\\x29) + Xc6\\x20+\\x20Zb1(YUc) \\x2b ZDo7 + Ol + HM\\x724 + TXe\\x38 + Gs4 + Pa\\x31);\\r\\nv\\x61\\x72 Gz = 672168;" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}