rule sig_20160303_c5cc06cbd98533066e634cb6ce5929f9 {
  meta:
    description = "datamaliciousorder - file 20160303_c5cc06cbd98533066e634cb6ce5929f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ca46ead126d3bf1fe7419b16da59d1d3ac4684d4c27d1a0f88e6511723c2a9c"

  strings:
    $s1  = "var BBDRc = \"DGGlZP hKd pt.Shell eoEJaGk Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var gUb = BuST(cBDg + \"B.\" + dBG[5]+(130394, dBG[4]));" fullword ascii
    $s3  = "var dBG = (Jxw + \"TTP\" + \" BKwoevi zPmMD XML ream St gKwExwPp AD XYghOec OD\").split(\" \");" fullword ascii
    $s4  = "return ZXWGtLo[0] + ZXWGtLo[2] + ZXWGtLo[4] + \".F\" + ZXWGtLo[7] + ZXWGtLo[9] + ZXWGtLo[12] + ZXWGtLo[14];" fullword ascii
    $s5  = "var zy = true  , cBDg = dBG[7] + \"\" + dBG[9];" fullword ascii
    $s6  = "var ZXWGtLo = \"Sc fsiyxiA r jWgDXSXDm ipting zgcsbpz OBA ile cUONLbzAmqMBuu System bM Vzayu Obj dTRMqa ect FBEDbAB\".split(\" " ascii
    $s7  = "jlQLg.open(ADvuP,CZsVJ,false);" fullword ascii
    $s8  = "function fAQfCMD(vUfi) {" fullword ascii
    $s9  = "return gHClY.status;" fullword ascii
    $s10 = "function wbeBuPD(TWWD) {" fullword ascii
    $s11 = "return new ActiveXObject(NfmHlF);" fullword ascii
    $s12 = "function hOTqwxvwL(wbXNc,npWTR,phwPA) {" fullword ascii
    $s13 = "tSR = K; break; " fullword ascii
    $s14 = "return LirGdbh" fullword ascii
    $s15 = "function YgWvMBTL() {" fullword ascii
    $s16 = "function jrJDE(NfmHlF) {" fullword ascii
    $s17 = "function IZia(FxYxT) {" fullword ascii
    $s18 = "function uRSvpYFzQ(FgFzlhFxlLX) {" fullword ascii
    $s19 = "function KhwZ(zRYjF,nOpHd) {" fullword ascii
    $s20 = "function JYTu(jlQLg,CZsVJ,ADvuP) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}