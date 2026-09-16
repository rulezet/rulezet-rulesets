rule sig_20160321_08af576a97dc23b31ec086255c404b15 {
  meta:
    description = "datamaliciousorder - file 20160321_08af576a97dc23b31ec086255c404b15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05ca0df81201cee7311dfc8720d177e40eed4fc8fb982d189c5e52eaad525282"

  strings:
    $s1  = "return WScript.CreateObject(rkaHp);" fullword ascii
    $s2  = "return ZszRTvF[0] + ZszRTvF[2] + ZszRTvF[4] + \".F\" + ZszRTvF[7] + ZszRTvF[9] + ZszRTvF[12] + ZszRTvF[14];" fullword ascii
    $s3  = "var KR = true  , epxf = rAE[7] + rAE[9] + rAE[11];" fullword ascii
    $s4  = "pQrdR.open(WOqPK,xZoKZ,false);" fullword ascii
    $s5  = "var rAE = (\"2.XMLHTTP GaHbgiC YmCCH XML ream St lJFRjtFI AD VfCjPVO O ItoK D\").split(\" \");" fullword ascii
    $s6  = "function yoSc(GjTtx) {" fullword ascii
    $s7  = "function kBDc(rkaHp) {" fullword ascii
    $s8  = "function OokjDhHED(ilLnOEczclV) {" fullword ascii
    $s9  = "function ngSeBfZjC(AqIBv) {" fullword ascii
    $s10 = "if (KNEOD == 413-213){return true;} else {return false;}" fullword ascii
    $s11 = "return sPjiF;" fullword ascii
    $s12 = "function hXrY(rUzwA,LwTKQ) {" fullword ascii
    $s13 = "function ivARdShS(PKf) {" fullword ascii
    $s14 = "function ABJm(KNEOD) {" fullword ascii
    $s15 = "if(o>=a.length) {break;}" fullword ascii
    $s16 = "function VkhD(WbqEr) {" fullword ascii
    $s17 = "function AUepGKZ(QRZx,bTNIl) {" fullword ascii
    $s18 = "function xYaov(Afartq) {" fullword ascii
    $s19 = "function sjxAUfW(lfxo) {" fullword ascii
    $s20 = "if (GjTtx > 191539-480){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}