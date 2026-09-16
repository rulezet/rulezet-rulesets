rule sig_20160309_1eb44295ab308b1e6d3abf5cac3c2630 {
  meta:
    description = "datamaliciousorder - file 20160309_1eb44295ab308b1e6d3abf5cac3c2630.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bcad3368793c22e3136f9e404a8e4da50ed0a778aa77cd507ccc216be34359a"

  strings:
    $s1  = "var Cvf = (\"2.XMLHTTP fDXrqfM bzYNH XML ream St dDoxEJZB AD Xaracom O KPrc D\").split(\" \");" fullword ascii
    $s2  = "return fKbsveW[0] + fKbsveW[2] + fKbsveW[4] + \".F\" + fKbsveW[7] + fKbsveW[9] + fKbsveW[12] + fKbsveW[14];" fullword ascii
    $s3  = "var iO = true  , SIgR = Cvf[7] + Cvf[9] + Cvf[11];" fullword ascii
    $s4  = "var fKbsveW = \"Sc DTXEhcV r tjDhkaRFr ipting vIZEuVF fLg ile LwvaqpJbuQqeRi System ZV NtMGE Obj ASqLMx ect nNGhsFd\".split(\" " ascii
    $s5  = "bAYRg.open(swYaI,dcLiW,false);" fullword ascii
    $s6  = "function CyXTwlI(XDUU,SKOZK) {" fullword ascii
    $s7  = "return XDUU.ExpandEnvironmentStrings(SKOZK);" fullword ascii
    $s8  = "function XQIc(bAYRg,dcLiW,swYaI) {" fullword ascii
    $s9  = "function FmglPyJBI(yjJLr,XzKSL,ESCfz,NyPQ) {" fullword ascii
    $s10 = "return hpwgF;" fullword ascii
    $s11 = "function aGjcjRrV() {" fullword ascii
    $s12 = "if (m >= YukEv.length) {break;}" fullword ascii
    $s13 = "if(I>=B.length) {break;}" fullword ascii
    $s14 = "function eJHuTYqb(wSr) {" fullword ascii
    $s15 = "function ImDQLyJ(HPvc) {" fullword ascii
    $s16 = "function JqGEftwcq(rUwuUrYtgMH) {" fullword ascii
    $s17 = "function phhh(HzfXp) {" fullword ascii
    $s18 = "function jLdT(eJhcV,pmMjR) {" fullword ascii
    $s19 = "return new ActiveXObject(upllzN);" fullword ascii
    $s20 = "return HPvc.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}