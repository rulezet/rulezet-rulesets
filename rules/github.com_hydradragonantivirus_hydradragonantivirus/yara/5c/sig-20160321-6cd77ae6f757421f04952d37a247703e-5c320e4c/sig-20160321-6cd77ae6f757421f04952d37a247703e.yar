rule sig_20160321_6cd77ae6f757421f04952d37a247703e {
  meta:
    description = "datamaliciousorder - file 20160321_6cd77ae6f757421f04952d37a247703e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8a6d48b9595b6354283c4d7de444a3582a57ea4cd0c54a009838efcc0cc1e5c"

  strings:
    $s1  = "return WScript.CreateObject(fMVsY);" fullword ascii
    $s2  = "return LUaHWwh[0] + LUaHWwh[2] + LUaHWwh[4] + \".F\" + LUaHWwh[7] + LUaHWwh[9] + LUaHWwh[12] + LUaHWwh[14];" fullword ascii
    $s3  = "var Fo = true  , hntg = nlc[7] + nlc[9] + nlc[11];" fullword ascii
    $s4  = "var LUaHWwh = FDQzm(cbUpsrLynk+\" \"+\"System Wa yRgsn Obj OabuYS ect XYMbEJC xUUaz\", \" \");" fullword ascii
    $s5  = "ccNOe.open(yzVsY,bYClI,false);" fullword ascii
    $s6  = "var nlc = (\"2.XMLHTTP qeeTMWR FxdzG XML ream St YnDpRskG AD rfQNfaM O VxwO D\").split(\" \");" fullword ascii
    $s7  = "function pghdEXe(Cntq) {" fullword ascii
    $s8  = "function FDQzm(Uci,eWLiQ) {" fullword ascii
    $s9  = "function mCQm(LeytA) {" fullword ascii
    $s10 = "function ahpc(fMVsY) {" fullword ascii
    $s11 = "function XxlAW(jggFfU) {" fullword ascii
    $s12 = "return aKMd.ExpandEnvironmentStrings(bmfpU);" fullword ascii
    $s13 = "function tXyV(UIzlm) {" fullword ascii
    $s14 = "if (SSuJd == 1139-939){return true;} else {return false;}" fullword ascii
    $s15 = "function KkugeQU(aKMd,bmfpU) {" fullword ascii
    $s16 = "function pqjxKwwtU(crSTEoPCSxf) {" fullword ascii
    $s17 = "function racS(SSuJd) {" fullword ascii
    $s18 = "function aoEl(TakAu) {" fullword ascii
    $s19 = "function QBNnPOeJ(dVz) {" fullword ascii
    $s20 = "if (NoUYn > 150516-330){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}