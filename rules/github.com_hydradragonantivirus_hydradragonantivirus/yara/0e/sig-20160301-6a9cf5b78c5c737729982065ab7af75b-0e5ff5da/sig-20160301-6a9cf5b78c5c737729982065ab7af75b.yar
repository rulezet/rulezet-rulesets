rule sig_20160301_6a9cf5b78c5c737729982065ab7af75b {
  meta:
    description = "datamaliciousorder - file 20160301_6a9cf5b78c5c737729982065ab7af75b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05c0464a0aa05dd03f8e30a28cc815c73b58c98d5cdc12ef9a1b710c142ebef0"

  strings:
    $s1  = "var fu = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(zXWxF);" fullword ascii
    $s3  = "var MBT = (TEz + \"TTP\" + \" ABHdVpZ gZuDD XML ream St oIMPspVn AD qnHrBwg OD\").split(\" \");" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + EdjLjgk + \".F\" + ZHQYLotRCR + neQFD + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var ww = true  , QPlY = MBT[7] + \"\" + MBT[9];" fullword ascii
    $s6  = "kegTy.open(VddNR,CcLTt,false);" fullword ascii
    $s7  = "function nvgF(tBaxe) {" fullword ascii
    $s8  = "hOh = K; break; " fullword ascii
    $s9  = "return nHhYS.status;" fullword ascii
    $s10 = "function PNFU(dblCW) {" fullword ascii
    $s11 = "function dmFmxYhj() {" fullword ascii
    $s12 = "function gLCs(tJQhL,ETZqf) {" fullword ascii
    $s13 = "function JSFr(nHhYS) {" fullword ascii
    $s14 = "function KrFn(eRKjX) {" fullword ascii
    $s15 = "return ZlVIu;" fullword ascii
    $s16 = "function QrFc(ygbnW) {" fullword ascii
    $s17 = "return new ActiveXObject(euvJJw);" fullword ascii
    $s18 = "function cSlg(FsZRX) {" fullword ascii
    $s19 = "function rAQHJ(euvJJw) {" fullword ascii
    $s20 = "function uHYIqHbCm(cDiFP,wrnTC,sPATb) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}