rule sig_20160310_cc222dad4a69c45efedf7290008052d7 {
  meta:
    description = "datamaliciousorder - file 20160310_cc222dad4a69c45efedf7290008052d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d1093fcf1925b7241ebcc80550cfe874d08ac3cca58dfec00af18daf85fdb1c"

  strings:
    $s1  = "return eWIpKcw[0] + eWIpKcw[2] + eWIpKcw[4] + \".F\" + eWIpKcw[7] + eWIpKcw[9] + eWIpKcw[12] + eWIpKcw[14];" fullword ascii
    $s2  = "var fm = true  , SJyf = CNP[7] + CNP[9] + CNP[11];" fullword ascii
    $s3  = "BqRfE.open(ESQeI,Ddsmq,false);" fullword ascii
    $s4  = "var CNP = (\"2.XMLHTTP dTbUxzr XRNvg XML ream St KiMNdNrW AD YuZqEeO O nBHI D\").split(\" \");" fullword ascii
    $s5  = "var eWIpKcw = \"Sc KmScezZ r cCghDzbzq ipting nBObnra YqG ile gIKQHnTTlTdjZU System bT BTWdD Obj ZBCYJY ect ksuplVY\".split(\" " ascii
    $s6  = "if(m>=X.length) {break;}" fullword ascii
    $s7  = "return fLaE.responseBody;" fullword ascii
    $s8  = "function SqXWb(dfzeFf) {" fullword ascii
    $s9  = "function hYRn(vNDpM,oscey) {" fullword ascii
    $s10 = "function Ixvv(BqRfE,Ddsmq,ESQeI) {" fullword ascii
    $s11 = "return new ActiveXObject(MrMpAP);" fullword ascii
    $s12 = "function yTJem(MrMpAP) {" fullword ascii
    $s13 = "if (MnMNp == 1001-801){return true;} else {return false;}" fullword ascii
    $s14 = "return Owmz.ExpandEnvironmentStrings(genjL);" fullword ascii
    $s15 = "function GRRx(MnMNp) {" fullword ascii
    $s16 = "return FeH.size;" fullword ascii
    $s17 = "qdO = m; break; " fullword ascii
    $s18 = "function pAIF(HqKxA,EsvFc) {" fullword ascii
    $s19 = "function fIgllODeM(hzgHg,kOWqI,tLPeP,mJUl) {" fullword ascii
    $s20 = "return VqYeU;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}