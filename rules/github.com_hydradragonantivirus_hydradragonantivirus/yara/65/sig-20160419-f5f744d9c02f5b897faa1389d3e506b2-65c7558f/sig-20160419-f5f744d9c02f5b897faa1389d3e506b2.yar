rule sig_20160419_f5f744d9c02f5b897faa1389d3e506b2 {
  meta:
    description = "datamaliciousorder - file 20160419_f5f744d9c02f5b897faa1389d3e506b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5f312c562c652d1aed5cb68da0edf4b7d45e69360c76bb576b6e9cf24d0db98"

  strings:
    $s1  = "return LJPzUZQ[0] + LJPzUZQ[2] + LJPzUZQ[4] + \".F\" + LJPzUZQ[7] + LJPzUZQ[9] + LJPzUZQ[12] + LJPzUZQ[14];" fullword ascii
    $s2  = "var aT = true  , vwCP = jjT[7] + jjT[9] + jjT[11];" fullword ascii
    $s3  = "var jjT = (\"2.XMLHTTP riWppZg GBhjr XML ream St LxOaXTpu AD LlccLRN O FBdc D\").split(\" \");" fullword ascii
    $s4  = "rWPi.open(pkHkn,TuMtu,false);" fullword ascii
    $s5  = "if(n>=g.length) {break;}" fullword ascii
    $s6  = "return urwex;" fullword ascii
    $s7  = "if (u >= qweEB.length) {break;}" fullword ascii
    $s8  = "function wpTrG(DsJ,EOtCQ) {" fullword ascii
    $s9  = "function vWcCu(EFYMlL) {" fullword ascii
    $s10 = "function krNx(auupv,xSOYL) {" fullword ascii
    $s11 = "return new ActiveXObject(vBpf);" fullword ascii
    $s12 = "return MmBgZHF;" fullword ascii
    $s13 = "function lnYx(AvpUO) {" fullword ascii
    $s14 = "return TBt.size;" fullword ascii
    $s15 = "function PskA(qweEB) {" fullword ascii
    $s16 = "if (AvpUO != 707-507){return false;} else {return true;}" fullword ascii
    $s17 = "function eSHCfN(YWtlTGj) {" fullword ascii
    $s18 = "function rPvSj(YFvRmb) {" fullword ascii
    $s19 = "return MrrBfhs[0];" fullword ascii
    $s20 = "function yKKU(MvzZL,lcUcZ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}