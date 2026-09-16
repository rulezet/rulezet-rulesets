rule sig_20160309_26d0c54cd1e351aac803a8ade102afa7 {
  meta:
    description = "datamaliciousorder - file 20160309_26d0c54cd1e351aac803a8ade102afa7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc8f2542ca2ba66576b17f0a9265f0f0d47676a71784057962fdb54ab2135c4d"

  strings:
    $s1  = "var Ga = true  , blgN = Nrc[7] + Nrc[9] + Nrc[11];" fullword ascii
    $s2  = "return JkRWzWK[0] + JkRWzWK[2] + JkRWzWK[4] + \".F\" + JkRWzWK[7] + JkRWzWK[9] + JkRWzWK[12] + JkRWzWK[14];" fullword ascii
    $s3  = "function GVcjfZH(prUN) {" fullword ascii
    $s4  = "FiMmp.open(vWSpI,bXROq,false);" fullword ascii
    $s5  = "var JkRWzWK = \"Sc lxiUrfY r VAOHZxYlO ipting romwQVa xFC ile ADXGtAxxMUBCDc System ce ibCmw Obj ApnDjO ect YYUVERs\".split(\" " ascii
    $s6  = "var Nrc = (\"2.XMLHTTP pKwEtUg ZsjiC XML ream St IizzSmyx AD lhzrFnR O hTdQ D\").split(\" \");" fullword ascii
    $s7  = "if(j>=e.length) {break;}" fullword ascii
    $s8  = "if (pPTmW == 303-103){return true;} else {return false;}" fullword ascii
    $s9  = "mZF = j; break; " fullword ascii
    $s10 = "function XuXdzoxR() {" fullword ascii
    $s11 = "function VZzJ(FiMmp,bXROq,vWSpI) {" fullword ascii
    $s12 = "return YUMgrJn" fullword ascii
    $s13 = "function Kxhc(IBeRe) {" fullword ascii
    $s14 = "function OOKq(pBLSW) {" fullword ascii
    $s15 = "return pBLSW.status;" fullword ascii
    $s16 = "return riZj.responseBody;" fullword ascii
    $s17 = "if (qZBvn > 174252-294){return true;} else {return false;}" fullword ascii
    $s18 = "return qb.ExpandEnvironmentStrings(ybxrv[6]+ybxrv[7]+ybxrv[8]);" fullword ascii
    $s19 = "function ZKaSjMNz(CUQ) {" fullword ascii
    $s20 = "return NGGio;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}