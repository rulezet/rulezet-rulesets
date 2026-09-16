rule sig_20160802_1011052d6fa1619e7ba8cb040628a000 {
  meta:
    description = "datamaliciousorder - file 20160802_1011052d6fa1619e7ba8cb040628a000.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1ef4ef146f7f977cb3ced76242058afad5a2cf1c3670c23d7d8641ede8ae558"

  strings:
    $s1  = "    var aUPg = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "770]=253;\\r\\x0aSq[\\x39632]=2\\x354;\\r\\nSq[160]=255;\\r\\n\\t\\r\\n\\tva\\x72 HFz=new Array();\\r\\n\\t\\x66or (var\\x20OPj=" ascii
    $s3  = "(\\x47z);\\r\\x0amash \\x3d null\\x3b\\r\\nvar random\\x20= functio\\x6e( range ) \\x7b\\r\\nre\\x74\\x75rn Math.flo\\x6f\\x72(r" ascii
    $s4  = "r\\nfunction V\\x4fy7(D\\x48f1 /* y  \\x2a/)\\r\\n{\\r\\n\\ti\\x66\\x20(D\\x48f1[0]== 0x\\x34D && DH\\x661[1]== 0x5a)\\x0d\\n\\t" ascii
    $s5  = "S\\x63ript[UIm \\x2b Yj(Sh\\x29](1000); \\x63\\x6fntinue;};\\r\\n\\x7d while (Uz);\\r\\n\\r\\nWScript.Q\\x75i\\x74\\x280)\\x3b" ascii
    $s6  = "\\r\\nvar Ep3 = \"43\" + \"\";\\r\\x0ava\\x72 Vh = \"th\" \\x2b \"\"\\x3b\\x0d\\nvar WKb = \"l\\x65ng\\x22 + \"\";\\r\\nfunction" ascii
    $s7  = "\\t\\r\\n\\treturn HFz;\\r\\n};\\x0d\\x0a\\x0d\\n\\r\\nf\\x75n\\x63tion Ly(DHf1 /* \\x79  */)\\r\\n{\\r\\n \\x20  var \\x50a7=ne" ascii
    $s8  = "\\x48y0=W\\x53cript[Wc + EIk + (function SWb(){return YFe;\\x7d()) + J\\x48u8]\\x28G\\x4au\\x2bOIo+STv0(VT\\x6b0)+Ih2 + \\x47Tg " ascii
    $s9  = "\\x28){re\\x74urn N\\x4cs;}()) + RGl2\\x2bHh+UIk+(func\\x74ion VEd(){retur\\x6e Uf;\\x7d()\\x29 + (funct\\x69\\x6fn Rz(){return " ascii
    $s10 = " + JHu8](GJu+OIo+(\\x66u\\x6ection Li4(){return \\x56Tk0;}(\\x29\\x29+I\\x682 + GT\\x67 + XH\\x620)\\x3b\\r\\n\\t\\tARt[E\\x6c](" ascii
    $s11 = "3\\x74ion Zq9\\x28){return Nl;}())+Wn1+RWi\\x2bPo+Cy5 + Nn5+(function GN\\x6e(){ret\\x75rn FYs1;}\\x28))+Rj3(Sj5), WSb0\\x2bHu +" ascii
    $s12 = "\" + \"\";\\r\\nvar Wc = \\x22C\\x72ea\\x22 + \"\";\\r\\nfuncti\\x6fn Bb5(\\x49Jh){return IJh;};va\\x72\\x20Hx \\x3d \"i\" +\\x2" ascii
    $s13 = "h4){return KKh4;};va\\x72 OXv9 = \"gth\" + \"\";\\r\\nvar QSc = \"len\" + \"\\x22;\\r\\nvar EYf = \"\\x56VV\" + \"\";\\r\\nvar I" ascii
    $s14 = "r \\x48u =\\x20\"tp\" + \"\";\\r\\nvar WSb0 = \"ht\" + \"\";\\x0d\\nfunction Rj3(TXh){return \\x54Xh\\x3b};var Sj5 = \"sye\"\\x2" ascii
    $s15 = "){return Tl8;};var Xe1 = \"h\" \\x2b \"\";\\r\\nvar Lm = \"pu\\x73\\x22\\x20+\\x20\"\";\\r\\nvar Rt\\x20= \"At\"\\x20+ \"\";\\x0" ascii
    $s16 = ")) + YFe + (function SS\\x71(){return JHu8;}())]((function GOk(){return Zk;}())\\x20+\\x20Qk1\\x20+ UJ\\x6c + ZYi);\\r\\nvar M" ascii
    $s17 = "r\\nva\\x72 CZy = \"V\\x56\"\\x20+ \"\";\\x0d\\nvar Jl9 = \"VVVV\\x56\" + \"\\x22;\\r\\nfunctio\\x6e \\x49f(\\x59Be){return YBe;" ascii
    $s18 = "ction \\x45P\\x6f(){return W\\x70\\x3b}()) + Xc6 + Zb1(YUc) + ZDo7 + Ol +\\x20\\x48Mr\\x34 + TXe8 + Gs4 + Pa1);\\r\\n\\x76ar Gz " ascii
    $s19 = "r\\nva\\x72 \\x49d=NV\\x64[QSc + OXv9];\\r\\nvar Pe0=(Dv3 \\x2b KJd + (function IMn(\\x29\\x7b\\x72eturn CZi8;}()), Zs5 + Te1 + " ascii
    $s20 = "6e=RJp2 + RIh + (func\\x74ion Zo4(){return JV\\x633;\\x7d());\\r\\n\\r\\nfunction\\x20uheprng\\x28) {re\\x74urn (function()\\x20" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}