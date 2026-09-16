rule sig_20160324_78524ab33ae8d7a0db269218ccdf0953 {
  meta:
    description = "datamaliciousorder - file 20160324_78524ab33ae8d7a0db269218ccdf0953.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c121e22c6cdf683cc9aa6ada0ba4a793541fc2640f8b23251b016e5546a34850"

  strings:
    $s1  = "return WScript.CreateObject(YSxxj);" fullword ascii
    $s2  = "var nB = true  , cUsd = oyN[7] + oyN[9] + oyN[11];" fullword ascii
    $s3  = "return ihYdVQy[0] + ihYdVQy[2] + ihYdVQy[4] + \".F\" + ihYdVQy[7] + ihYdVQy[9] + ihYdVQy[12] + ihYdVQy[14];" fullword ascii
    $s4  = "var oyN = (\"2.XMLHTTP GlmMXpI jWxTC XML ream St ABTcpwdr AD PNjsCeU O pYia D\").split(\" \");" fullword ascii
    $s5  = "BQZT.open(KtFeb,qtqXZ,false);" fullword ascii
    $s6  = "var ihYdVQy = rmqPF(NHFVyDfyLA+\" \"+\"System hA fYhRU Obj roJpbG ect jEvMnMZ joUhi\", \" \");" fullword ascii
    $s7  = "if(F>=j.length) {break;}" fullword ascii
    $s8  = "function OYKx(wXMMl) {" fullword ascii
    $s9  = "return JwfgUQy(IM,mMsmW[287-281]+mMsmW[878-871]+mMsmW[265-257]);" fullword ascii
    $s10 = "return qMwJZF/*JqjNkYMyWfTnpdQQTv7W5V35P*/.position=282-282;" fullword ascii
    $s11 = "function rmqPF(KEJ,dsViE) {" fullword ascii
    $s12 = "return DVBdY.status;" fullword ascii
    $s13 = "function iRziYAjfB(kbBjXBFaZMi) {" fullword ascii
    $s14 = "function TQwPmwq(BZUJ) {" fullword ascii
    $s15 = "function yDKdj(qMwJZF) {" fullword ascii
    $s16 = "if (g >= ozviv.length) {break;}" fullword ascii
    $s17 = "function kdhO(BbIJb,qtqXZ,KtFeb) {" fullword ascii
    $s18 = "function DTYqP(SpvJFA) {" fullword ascii
    $s19 = "function VOAE(ozviv) {" fullword ascii
    $s20 = "function lBKTjAVq(hDne) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}